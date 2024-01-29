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

#ifndef _SOURCES_COMMON_CORRELATOR_TYPES_H_
#define _SOURCES_COMMON_CORRELATOR_TYPES_H_

#define CORRELATOR_IP_MAX 128

#ifdef __cplusplus
#include <stdint.h>
#endif

// The following macros define where the correlation information is
// collected from.
#define OPENSSL_LEVEL       1
#define TCP_LEVEL           2

typedef struct {
  uint8_t laddr[CORRELATOR_IP_MAX];
  uint8_t raddr[CORRELATOR_IP_MAX];
  uint32_t llen;
  uint32_t rlen;
  uint32_t lport;
  uint32_t rport;
  uint64_t conn_id;
} correlator_ip_t;

typedef enum{
  kSslNewConnection,
  kSslCorrelationInfo,
  kSslMax
} OpenSslCorrelationType;

typedef struct {
  uint32_t type;  // OpenSslCorrelationType
  uint64_t conn_id;
}openssl_mdata_t;

/*If you increase the size of this structure also increase the size of buffer
in openssl correlator*/
typedef struct {
  openssl_mdata_t mdata;
  uint8_t info[24];
} openssl_correlation;

// In case the mdata signifies type kSslCorrelationInfo
// this struct will be used to carry information.
typedef struct data_sample {
  uint64_t data;
  uint8_t level;
}data_sample_t;

#endif
