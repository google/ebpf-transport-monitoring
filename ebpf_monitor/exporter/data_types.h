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

#ifndef _EBPF_MONITOR_EXPORTER_DATA_TYPES_H_
#define _EBPF_MONITOR_EXPORTER_DATA_TYPES_H_

#include <sys/types.h>

#include <cstdint>
#include <string>

namespace ebpf_monitor {

enum class MetricType {
  kUint8,
  kUint16,
  kUint32,
  kUint64,
  kInt8,
  kInt16,
  kInt32,
  kInt64,
  kFloat,
  kDouble,
  kInternal,
};

enum class MetricUnitType { kNone, kTime, kData };

enum class MetricTimeType { kNsec, kUsec, kMsec, kSec, kMin, kHour };

enum class MetricDataType {
  kBytes,
  kKbytes,
  kMbytes,
  kGbytes,
  kBits,
  kKbits,
  kMbits,
  kGbits,
};

typedef struct MetricUnit {
  MetricUnitType type;
  union {
    MetricDataType data;
    MetricTimeType time;
  };
} MetricUnit_t;

enum class MetricKind {
  // Error Kind
  kNone,
  // The value is measured at a specific instant in time.
  kGauge,
  // The value measures the change since it was last recorded.
  kDelta,
  // The value constantly increases over time.
  kCumulative,
  // The value is a distribution
  kDistribution,
};

static std::string DataTypeString(MetricDataType type) {
  switch (type) {
    case MetricDataType::kBytes:
      return "Bytes";
    case MetricDataType::kKbytes:
      return "Kilobytes";
    case MetricDataType::kMbytes:
      return "Megabytes";
    case MetricDataType::kGbytes:
      return "Gigabytes";
    case MetricDataType::kBits:
      return "Bits";
    case MetricDataType::kKbits:
      return "KiloBits";
    case MetricDataType::kMbits:
      return "MegaBits";
    case MetricDataType::kGbits:
      return "GigaBits";
  }
  return "";
}

static std::string TimeTypeString(MetricTimeType type) {
  switch (type) {
    case MetricTimeType::kNsec:
      return "ns";
    case MetricTimeType::kUsec:
      return "us";
    case MetricTimeType::kMsec:
      return "ms";
    case MetricTimeType::kSec:
      return "s";
    case MetricTimeType::kMin:
      return "min";
    case MetricTimeType::kHour:
      return "h";
  }
  return "";
}

static __attribute__((unused)) std::string GetUnitString(MetricUnit_t unit) {
  switch (unit.type) {
    case MetricUnitType::kTime:
      return TimeTypeString(unit.time);
    case MetricUnitType::kData:
      return DataTypeString(unit.data);
    case MetricUnitType::kNone:
      return "";
  }
  return "";
}

static __attribute__((unused)) size_t getSize(MetricType m) {
  switch (m) {
    case MetricType::kUint8:
      return sizeof(uint8_t);
    case MetricType::kUint16:
      return sizeof(uint16_t);
    case MetricType::kUint32:
      return sizeof(uint32_t);
    case MetricType::kUint64:
      return sizeof(uint64_t);
    case MetricType::kInt8:
      return sizeof(int8_t);
    case MetricType::kInt16:
      return sizeof(int16_t);
    case MetricType::kInt32:
      return sizeof(int32_t);
    case MetricType::kInt64:
      return sizeof(int64_t);
    case MetricType::kFloat:
      return sizeof(float);
    case MetricType::kDouble:
      return sizeof(double);
    case MetricType::kInternal:
      return 0;
  }
  return 0;
}

struct MetricDesc {
  MetricType key_type;
  MetricType value_type;
  MetricKind kind;
  MetricUnit_t unit;
};

struct LogDesc {};

}  // namespace ebpf_monitor

#endif  // _EBPF_MONITOR_EXPORTER_DATA_TYPES_H_
