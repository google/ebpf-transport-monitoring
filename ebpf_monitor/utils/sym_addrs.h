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

#ifndef _EBPF_MONITOR_UTILS_SYM_ADDRS_H_
#define _EBPF_MONITOR_UTILS_SYM_ADDRS_H_

#ifdef __cplusplus
#include <cstdint>
#endif

typedef enum sym_location_type__ {
  kLocationTypeInvalid = 0,
  kLocationTypeStack = 1,
  kLocationTypeRegisters = 2
} sym_location_type_t;

typedef struct sym_location__ {
  sym_location_type_t type;
  int32_t offset;
} sym_location_t;

typedef struct member_var_ {
  int32_t offset;
  int32_t size;
} member_var_t;

#endif  // _EBPF_MONITOR_UTILS_SYM_ADDRS_H_
