// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ebpf_monitor/utils/elf_reader.h"

#include <cxxabi.h>  // IWYU pragma: keep
#include <fcntl.h>
#include <string.h>
#include <sys/auxv.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "elf.h"
#include "gelf.h"
#include "libelf.h"

namespace ebpf_monitor {

#define GET_TYPE(x) (((unsigned int)x) & 0xf)
ElfReader::ElfReader(std::string path) : binary_path_(path) {}

static absl::StatusOr<int> OpenElf(const char * path, Elf **elf_out) {
  int fd_out = open(path, O_RDONLY);
  if (fd_out < 0) {
    return absl::NotFoundError("Binary path cannot be opened");
  }
  if (elf_version(EV_CURRENT) == EV_NONE) {
    return absl::InternalError("Elf library too old");
  }
  *elf_out = elf_begin(fd_out, ELF_C_READ, nullptr);
  if (*elf_out == nullptr) {
    close(fd_out);
    return absl::FailedPreconditionError("Unable to open read elf file");
  }
  return fd_out;
}

static absl::StatusOr<uint64_t> GetSearchValue(Elf *e, GElf_Sym *sym,
                                               ElfReader::SearchType type) {
  if (type == ElfReader::kOffset) {
    Elf_Scn *sym_scn;
    GElf_Shdr sym_sh;
    sym_scn = elf_getscn(e, sym->st_shndx);
    if (!sym_scn) {
      return absl::InternalError("Could not find symbol section");
    }
    if (!gelf_getshdr(sym_scn, &sym_sh)) {
      return absl::InternalError("Could not find section header");
    }
    return sym->st_value - sym_sh.sh_addr + sym_sh.sh_offset;
  } else if (type == ElfReader::kValue) {
    return sym->st_value;
  }
  return absl::InternalError("Unknown Search Type");
}

static absl::StatusOr<std::string> CheckSymbolName(
        const absl::flat_hash_set<std::string> &symbols,
        const std::string& name) {
  for (auto it = symbols.begin(); it != symbols.end(); it++) {
    size_t pos = name.find(*it);
    // The second condition is to avoid matching to no named structs
    if (pos != std::string::npos &&
        (pos + it->length() == name.length())) {
      return *it;
    }
  }
  return absl::NotFoundError("Symbol not found");
}

absl::StatusOr<int> ElfReader::CheckSection(
    Elf *e, Elf_Scn *section,
    const absl::flat_hash_set<std::string> &symbols,
    ElfReader::SearchType type) {
  Elf_Data *data = nullptr;
  GElf_Shdr header;

  uint32_t count = 0;

  if (!gelf_getshdr(section, &header))
    return absl::InternalError("Invalid section");

  while ((data = elf_getdata(section, data)) != nullptr) {
    size_t i, symcount = data->d_size / header.sh_entsize;

    if (data->d_size % header.sh_entsize != 0) {
      return absl::InternalError("Read data seems incorrect");
    }

    for (i = 0; i < symcount; ++i) {
      GElf_Sym sym;
      const char *name;

      if (!gelf_getsym(data, (int)i, &sym)) continue;

      if ((name = elf_strptr(e, header.sh_link, sym.st_name)) == nullptr)
        continue;
      if (name[0] == 0) continue;
      if (sym.st_value == 0) continue;

      if ((!strncmp(name, "_Z", 2) || !strncmp(name, "___Z", 4))) {
        char *demangled_name =
            abi::__cxa_demangle(name, nullptr, nullptr, nullptr);
        if (demangled_name == nullptr) {
          continue;
        }
        auto search_name =
            CheckSymbolName(symbols, std::string(demangled_name));
        if (search_name.ok()) {
          auto offset = GetSearchValue(e, &sym, type);
          if (offset.ok()) {
            symbols_[*search_name] = *offset;
            count++;
          }
        }
        free(demangled_name);
      } else {
        std::string s_name(name);
        auto search_name = CheckSymbolName(symbols, s_name);
        if (search_name.ok()) {
          auto offset = GetSearchValue(e, &sym, type);
          if (offset.ok()) {
            symbols_[*search_name] = *offset;
            count++;
          }
        }
      }
    }
  }
  return count;
}

absl::StatusOr<uint64_t> ElfReader::GetSymbol(absl::string_view symbol){
  if (symbols_.find(symbol) != symbols_.end()) {
    return symbols_[symbol];
  }
  return absl::NotFoundError(absl::StrFormat("Symbol %s not found", symbol));
}

absl::Status ElfReader::FindSymbols(
    const absl::flat_hash_set<std::string>& symbols,
    SearchType type) {
  Elf_Scn *section = nullptr;
  Elf *e;
  GElf_Ehdr ehdr;
  absl::Status status;

  int count = 0;
  symbols_.clear();
  auto fd = OpenElf(binary_path_.c_str(), &e);
  if (!fd.ok()) return fd.status();

  if (gelf_getehdr(e, &ehdr) == nullptr) {
    status = absl::InternalError("Unable to read ehdr");
    goto close;
  }
  while ((section = elf_nextscn(e, section)) != nullptr) {
    GElf_Shdr header;

    if (!gelf_getshdr(section, &header)){
      continue;
    }
    if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM){
      continue;
    }

    const char *name = elf_strptr(e, ehdr.e_shstrndx, header.sh_name);
    section_offsets_[name] = {.offset = header.sh_offset,
                              .addr = header.sh_addr};

    auto found = CheckSection(e, section, symbols, type);
    if (!found.ok()) {
      std::cerr <<  found.status() << "\n";
    } else {
      count += *found;
    }
    if (count == symbols.size()) break;
  }
  status = absl::OkStatus();
close:
  elf_end(e);
  close(*fd);
  return status;
}

absl::Status ElfReader::GetSectionOffset(const char *section_name,
                                         struct section_data *data) {
  Elf_Scn *section = nullptr;
  GElf_Ehdr ehdr;
  Elf *e;
  absl::Status status;

  if (section_name == nullptr) {
    return absl::InvalidArgumentError("section_name is nullptr");
  }
  if (data == nullptr) {
    return absl::InvalidArgumentError("data is nullptr");
  }
  if (section_offsets_.find(section_name) != section_offsets_.end()) {
    *data = section_offsets_[section_name];
    return absl::OkStatus();
  }

  auto fd = OpenElf(binary_path_.c_str(), &e);
  if (!fd.ok()) return fd.status();

  if (gelf_getehdr(e, &ehdr) == nullptr) {
    status = absl::InternalError("Unable to read ehdr");
    goto close;
  }

  while ((section = elf_nextscn(e, section)) != nullptr) {
    GElf_Shdr header;
    if (!gelf_getshdr(section, &header)) continue;
    const char *name = elf_strptr(e, ehdr.e_shstrndx, header.sh_name);
    section_offsets_[name] = {.offset = header.sh_offset,
                              .addr = header.sh_addr};
    if (strcmp(name, section_name) == 0) {
      data->offset = header.sh_offset;
      data->addr = header.sh_addr;
      status = absl::OkStatus();
      goto close;
    }
  }

  data->offset = 0;
  data->addr = 0;
  status = absl::NotFoundError("Section not found");
close:
  elf_end(e);
  close(*fd);
  return status;
}

absl::Status ElfReader::ReadData(const char *section_name, uint64_t offset,
                                 char *buffer, uint32_t size) {
  int read_offset = offset;
  if (section_name != nullptr) {
    struct section_data text_section;
    auto status = GetSectionOffset(section_name, &text_section);
    if (!status.ok()) return status;
    read_offset = offset - text_section.addr + text_section.offset;
  }

  std::ifstream ifs(binary_path_, std::ios::binary);
  if (!ifs.seekg(read_offset)) {
    return absl::InternalError("Failed to seek offset");
  }
  if (!ifs.read(buffer, size)) {
    ifs.close();
    return absl::InternalError("Failed to read data");
  }

  if (ifs.gcount() != size) {
    ifs.close();
    return absl::InternalError("Read data seems incorrect");
  }

  ifs.close();
  return absl::OkStatus();
}

absl::StatusOr<uint32_t> ElfReader::GetKernelVersion(){
  // Get VDSO section in this binary
  char* vdso = (char*) getauxval(AT_SYSINFO_EHDR);
  if (!vdso){
    return absl::InternalError("Could not find vdso");
  }

  int page_size = getauxval(AT_PAGESZ);
  if (!page_size) {
    // Assume 4K page size
    page_size = 0x1000;
  }

  Elf *elf = elf_memory(vdso, page_size);

  if (elf == nullptr) {
    return absl::InternalError("Could not find elf section");
  }

  GElf_Ehdr ehdr;
  if (gelf_getehdr(elf, &ehdr) == nullptr) {
    return absl::InternalError("Unable to read ehdr");
  }

  // elf_getscn was unable to iterate through sections,
  // hence manually iterating through sections
  for (int i = 0; i < ehdr.e_shnum; i++)
  {
    auto shdr = (GElf_Shdr *)((char*)vdso + ehdr.e_shoff +
                                              (i * ehdr.e_shentsize));
    if (shdr->sh_type != SHT_NOTE) continue;

    const char * ptr = (const char *)((char*)vdso + shdr->sh_offset);
    const char * end = ptr + shdr->sh_size;

    while (ptr < end){
      GElf_Nhdr *nhdr = (GElf_Nhdr *)ptr;
      ptr += sizeof(GElf_Nhdr);

      const char* name = ptr;
      // Word aligning the pointer
      ptr += (nhdr->n_namesz + sizeof(GElf_Word)) & -sizeof(GElf_Word);

      const uint32_t * desc = (const uint32_t*)ptr;
      ptr += (nhdr->n_descsz + sizeof(GElf_Word)) & -sizeof(GElf_Word);

      if ((nhdr->n_namesz > 5 && !memcmp(name, "Linux", 5)) &&
          nhdr->n_descsz == 4 && !nhdr->n_type){
        return *desc;
      }
    }
  }
  return absl::InternalError("Could not find version number");
}

}  // namespace ebpf_monitor
