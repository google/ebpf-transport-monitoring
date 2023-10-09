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

#include "exporters/gce_metadata.h"

#include <stdlib.h>

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "curl/curl.h"
#include "curl/easy.h"

namespace ebpf_monitor {

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = (char *)realloc(mem->memory, realsize + 1);
  if (mem->memory == NULL) {
    /* out of memory */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  memcpy(&(mem->memory[0]), contents, realsize);
  mem->size = realsize + 1;
  mem->memory[mem->size-1] = 0;
  return realsize;
}

CURL *SetupHandle(struct MemoryStruct *chunk) {
  CURL *curl_handle;

  curl_global_init(CURL_GLOBAL_ALL);
  curl_handle = curl_easy_init();
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)chunk);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  struct curl_slist *list;
  list = curl_slist_append(NULL, "Metadata-Flavor: Google");
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, list);
  return curl_handle;
}

absl::StatusOr<absl::flat_hash_map<std::string, std::string>>
GCEMetadata::GetGCEMetadata() {
  CURLcode res;
  struct MemoryStruct chunk;

  chunk.memory =
      (char *)malloc(1); /* will be grown as needed by the realloc above */
  chunk.size = 0;        /* no data at this point */
  CURL *curl_handle = SetupHandle(&chunk);
  absl::flat_hash_map<std::string, std::string> labels;
  absl::flat_hash_map<std::string, std::string> urls = {
      {"Zone",
       "http://metadata.google.internal/computeMetadata/v1/instance/zone"},
      {"InstanceId",
       "http://metadata.google.internal/computeMetadata/v1/instance/id"},
      {"ProjectId",
       "http://metadata.google.internal/computeMetadata/v1/project/"
       "project-id"}};

  for (auto iter = urls.begin(); iter != urls.end(); ++iter) {
    curl_easy_setopt(curl_handle, CURLOPT_URL, iter->second.c_str());
    res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
      return absl::InternalError(
          absl::StrFormat("Could not query metadata %s %s %s", iter->first,
                          iter->second, curl_easy_strerror(res)));
    } else {
      labels[iter->first] = chunk.memory;
    }
  }

  curl_easy_cleanup(curl_handle);
  free(chunk.memory);
  curl_global_cleanup();

  return labels;
}

}  // namespace ebpf_monitor
