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

#ifndef _SOURCES_COMMON_SYM_HELPERS_H_
#define _SOURCES_COMMON_SYM_HELPERS_H_

#ifndef CORE
#include <linux/binfmts.h>
#include <uapi/linux/ptrace.h>
#endif
#include "bpf/bpf_helpers.h"  // NOLINT(build/include)
#include "defines.h"
#include "sym_addrs.h"  // NOLINT(build/include)
#include "sym_types.h"  // NOLINT(build/include)

#define NUM_REGS    9
// Check that userspace populated the corresponding symbol offset
#define CHECK_SYM_LOC(symaddr) \
  (symaddr.offset >= 0 || symaddr.type != kLocationTypeInvalid)

#define REQUIRE_SYM_LOC(symaddr) \
  if (!CHECK_SYM_LOC(symaddr)) { \
    return -1;                   \
  }

#define CHECK_MEM_VAR(memvar) (memvar.offset >= 0)

#define REQUIRE_MEM_VAR(offset, dest)                         \
  if (!CHECK_MEM_VAR(offset) && sizeof(dest) < offset.size) { \
    return -1;                                                \
  }

#define READ_MEMBER(base, loc, data) \
  bpf_probe_read(data, sizeof(*data), base + loc.offset)

// Contains the registers of the golang register ABI.
// This struct is required because we use it in the regs_heap BPF map, which
// enables us to allocate this memory on the BPF heap instead of the BPF map.
struct go_regabi_regs {
  uint64_t regs[NUM_REGS];
};

// The BPF map used to store the registers of Go's register-based
// calling convention.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct go_regabi_regs));
  __uint(max_entries, 1);
} regs_heap SEC(".maps");

// Copies the registers of the golang ABI, so that they can be
// easily accessed using an offset.
static __inline uint64_t* go_regabi_regs(const struct pt_regs* ctx) {
  uint32_t kZero = 0;
  struct go_regabi_regs* regs_heap_var =
      bpf_map_lookup_elem(&regs_heap, &kZero);
  if (unlikely(regs_heap_var == NULL)) {
    return NULL;
  }

  regs_heap_var->regs[0] = ctx->ax;
  regs_heap_var->regs[1] = ctx->bx;
  regs_heap_var->regs[2] = ctx->cx;
  regs_heap_var->regs[3] = ctx->di;
  regs_heap_var->regs[4] = ctx->si;
  regs_heap_var->regs[5] = ctx->r8;
  regs_heap_var->regs[6] = ctx->r9;
  regs_heap_var->regs[7] = ctx->r10;
  regs_heap_var->regs[8] = ctx->r11;
  return regs_heap_var->regs;
}

static __inline long read_variable(void* arg, size_t arg_size,
                                   const volatile sym_location_t* loc,
                                   const void* sp, uint64_t* regs) {
  if (likely(loc->type == kLocationTypeRegisters)) {
    uint32_t offset = loc->offset;
    if (offset < NUM_REGS) {
      return bpf_probe_read(arg, arg_size, (char*)(regs + offset));
    }
  } else if (loc->type == kLocationTypeStack) {
    return bpf_probe_read(arg, arg_size, sp + loc->offset);
  }
  return -1;
}

#endif  //_SOURCES_COMMON_SYM_HELPERS_H_
