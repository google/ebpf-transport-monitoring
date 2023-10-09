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

#include "exporters/oc_gcp_exporter.h"

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "events.h"
#include "exporters/exporters_util.h"
#include "exporters/gce_metadata.h"
#include "google/monitoring/v3/metric_service.grpc.pb.h"
#include "grpcpp/security/credentials.h"
#include "opencensus/exporters/stats/stackdriver/stackdriver_exporter.h"
#include "opencensus/stats/stats.h"

constexpr absl::Duration LOGGING_INTERVAL = absl::Minutes(1);
constexpr uint32_t LOGS_PER_REQUEST = 199;

namespace ebpf_monitor {

using ::opencensus::stats::Aggregation;
using ::opencensus::stats::BucketBoundaries;
using ::opencensus::stats::MeasureInt64;
using ::opencensus::stats::ViewDescriptor;

const char kStatsPrefix[] = "ebpf_prober/";
constexpr char kGoogleStackdriverStatsAddress[] = "monitoring.googleapis.com";

std::string OCDataTypeString(MetricDataType type) {
  switch (type) {
    case MetricDataType::kBytes:
      return "By";
    case MetricDataType::kKbytes:
      return "kBy";
    case MetricDataType::kMbytes:
      return "MBy";
    case MetricDataType::kGbytes:
      return "GBy";
    case MetricDataType::kBits:
      return "bit";
    case MetricDataType::kKbits:
      return "kbit";
    case MetricDataType::kMbits:
      return "Mbits";
    case MetricDataType::kGbits:
      return "Gbits";
  }
  return "";
}

Aggregation DataDistributionAggregation() {
  return Aggregation::Distribution(BucketBoundaries::Explicit(
      {0, 1024, 2048, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216,
       67108864, 268435456, 1073741824, 4294967296}));
}

Aggregation TimeDistributionAggregation() {
  return Aggregation::Distribution(BucketBoundaries::Explicit(
      {0,   10 , 50, 100,  300,   600,   800,   1000,     2000,   4000,
       6000,  10000,   13000,    16000,    20000,    25000,  30000,
       40000,   50000 , 65000,  80000,   100000,  130000,  160000, 200000,
       250000,   300000,   400000, 500000, 650000, 800000, 1000000}));
}

Aggregation CountDistributionAggregation() {
  return Aggregation::Distribution(BucketBoundaries::Exponential(17, 1.0, 2.0));
}

OCGCPMetricExporter::OCGCPMetricExporter(std::string project_name,
                                         AggregationLevel agg)
    : project_(project_name), agg_(agg), default_tag_map_(nullptr) {}

OCGCPMetricExporter::OCGCPMetricExporter(std::string project_name,
                                         std::string service_file_path,
                                         AggregationLevel agg)
    : project_(project_name),
      service_file_path_(service_file_path),
      agg_(agg),
      default_tag_map_(nullptr) {}

std::unique_ptr<google::monitoring::v3::MetricService::StubInterface>
OCGCPMetricExporter::MakeMetricServiceStub(std::string& json_text) {
  grpc::ChannelArguments args;
  args.SetUserAgentPrefix("stackdriver_exporter");
  std::shared_ptr<::grpc::ChannelCredentials> credential;
  if (service_file_path_.empty()) {
    // The credential file path is configured by environment variable
    // GOOGLE_APPLICATION_CREDENTIALS
    credential = ::grpc::GoogleDefaultCredentials();
  } else {
    auto jwt_creds = ::grpc::ServiceAccountJWTAccessCredentials(json_text);
    auto ssl_creds = ::grpc::SslCredentials(grpc::SslCredentialsOptions{});
    credential = ::grpc::CompositeChannelCredentials(ssl_creds, jwt_creds);
  }
  auto channel = ::grpc::CreateCustomChannel(kGoogleStackdriverStatsAddress,
                                             credential, args);
  return google::monitoring::v3::MetricService::NewStub(channel);
}

absl::Status OCGCPMetricExporter::Init() {
  GetTags();
  std::string json_text;
  if (!service_file_path_.empty()) {
    auto creds = std::ifstream(service_file_path_);
    if (!creds.is_open()) {
      return absl::NotFoundError("Service file creds cannot be opened");
    }
    json_text = std::string(std::istreambuf_iterator<char>(creds.rdbuf()), {});
  }
  opencensus::exporters::stats::StackdriverOptions stats_opts;
  stats_opts.project_id = project_;
  stats_opts.metric_service_stub = MakeMetricServiceStub(json_text);
  opencensus::exporters::stats::StackdriverExporter::Register(
      std::move(stats_opts));

  return absl::OkStatus();
}

static std::string OCGetUnitString(MetricUnit_t unit) {
  switch (unit.type) {
    case MetricUnitType::kTime:
      // we always convert to micro seconds
      return TimeTypeString(MetricTimeType::kUsec);
    case MetricUnitType::kData:
      return OCDataTypeString(unit.data);
    case MetricUnitType::kNone:
      return "";
  }
  return "";
}

void OCGCPMetricExporter::GetMesure(std::string& name, const MetricDesc& desc) {
  measures_.insert({name, opencensus::stats::MeasureInt64::Register(
                              absl::StrCat(kStatsPrefix, "measure/", name), "",
                              OCGetUnitString(desc.unit))});
}

void OCGCPMetricExporter::GetTags() {
  auto metadata = GCEMetadata::GetGCEMetadata();
  if (!metadata.ok()) {
    std::cerr << "WARN: Unable to find GCE metadata: " << metadata.status()
              << std::endl;
  } else {
    gce_metadata_ = *metadata;
  }

  if (!gce_metadata_.empty()) {
    for (const auto& it : gce_metadata_) {
      auto tag = opencensus::tags::TagKey::Register(it.first);
      default_tag_vector_.push_back(std::make_pair(tag, it.second));
    }
  } else {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    auto tag = opencensus::tags::TagKey::Register("hostname");
    default_tag_vector_.push_back(std::make_pair(tag, hostname));
  }

  default_tag_map_ =
      std::make_unique<opencensus::tags::TagMap>(default_tag_vector_);
}

absl::StatusOr<opencensus::stats::Aggregation> GetAggregation(
    std::string& name, const MetricDesc& desc) {
  switch (desc.kind) {
    case MetricKind::kGauge:
      return Aggregation::LastValue();
    case MetricKind::kDelta:
      return Aggregation::Sum();
    case MetricKind::kCumulative:
      return Aggregation::Sum();
    case MetricKind::kDistribution:
      switch (desc.unit.type) {
        case MetricUnitType::kTime:
          return ebpf_monitor::TimeDistributionAggregation();
        case MetricUnitType::kData:
          return ebpf_monitor::DataDistributionAggregation();
        case MetricUnitType::kNone:
          return ebpf_monitor::CountDistributionAggregation();
      }
    default:
      break;
  }
  return absl::InternalError("Unknown Aggregation");
}

absl::Status OCGCPMetricExporter::RegisterMetric(std::string name,
                                                 const MetricDesc& desc) {
  if (measures_.find(name) != measures_.end()) {
    return absl::AlreadyExistsError("metric already registered");
  }
  if (correlators_.empty()) {
    return absl::InternalError(
        "Correlator needs to be registered before metrics");
  }
  if (desc.kind == MetricKind::kNone) {
    return absl::InternalError("Invalid Metric Kind");
  }
  metrics_[name] = desc;
  GetMesure(name, desc);
  auto descriptor = ViewDescriptor()
          .set_name(absl::StrCat(kStatsPrefix, name))
          .set_description("The length of the lines read in")
          .set_measure(absl::StrCat(kStatsPrefix, "measure/", name));

  auto agg = GetAggregation(name, desc);
  if (!agg.ok()) {
    return agg.status();
  }
  descriptor.set_aggregation(*agg);
  descriptor.set_expiry_duration(absl::Seconds(300));

  for (auto& tag : default_tag_vector_) {
    descriptor.add_column(tag.first);
  }
  if (agg_ == AggregationLevel::kConnection) {
    std::vector<std::string> labels;
    for (auto& correlator : correlators_) {
      auto src = correlator->GetLabelKeys();
      labels.insert(labels.end(),
                    std::make_move_iterator(src.begin()),
                    std::make_move_iterator(src.end()));
    }
    for (const auto& it : labels) {
      descriptor.add_column(opencensus::tags::TagKey::Register(it));
    }
    descriptor.add_column(opencensus::tags::TagKey::Register("local_ip"));
    descriptor.add_column(opencensus::tags::TagKey::Register("remote_ip"));
  }
  descriptor.RegisterForExport();
  return absl::OkStatus();
}

opencensus::tags::TagMap&
  OCGCPMetricExporter::GetTagMap(const std::string& uuid,
                              std::shared_ptr<CorrelatorInterface> correlator) {
  if (agg_ == AggregationLevel::kConnection) {
    auto it = tag_maps_.find(uuid);
    if (it != tag_maps_.end()) {
      return *(it->second);
    }

    auto tag_vector = default_tag_vector_;
    size_t pos = uuid.find("->");
    std::string local_ip = uuid.substr(0, pos);
    std::string remote_ip = uuid.substr(pos+2);
    tag_vector.push_back(
        std::make_pair(opencensus::tags::TagKey::Register("local_ip"),
                       local_ip));
    tag_vector.push_back(
        std::make_pair(opencensus::tags::TagKey::Register("remote_ip"),
                       remote_ip));
    auto labels = correlator->GetLabels(uuid);
    for (const auto& label : labels) {
      tag_vector.push_back(std::make_pair(
          opencensus::tags::TagKey::Register(label.first), label.second));
    }

    tag_maps_[uuid] = new opencensus::tags::TagMap(tag_vector);
    return *tag_maps_[uuid];
  }
  return *default_tag_map_;
}

static uint64_t GetUs(uint64_t val, MetricTimeType type) {
  switch (type) {
    case MetricTimeType::kNsec:
      return val / 1000;
    case MetricTimeType::kUsec:
      return val;
    case MetricTimeType::kMsec:
      return val * 1000;
    case MetricTimeType::kSec:
      return val * 1000 * 1000;
    case MetricTimeType::kMin:
      return val * 60 * 1000 * 1000;
    case MetricTimeType::kHour:
      return val * 3600 * 1000 * 1000;
  }
  // This will not happen;
  static_assert(true);
  return 0;
}

absl::Status OCGCPMetricExporter::HandleData(absl::string_view metric_name,
                                             void* key,
                                             void* value) {
  auto it = metrics_.find(metric_name);
  if (it == metrics_.end()) {
    return absl::NotFoundError("metric_name not found");
  }
  metric_format_t* metric = (metric_format_t*)value;
  auto metric_desc = metrics_.find(metric_name);

  absl::StatusOr<std::string> uuid;
  std::shared_ptr<CorrelatorInterface> correlator;
  for (auto& it : correlators_) {
    uuid = it->GetUUID(*(uint64_t*)key);
    if (uuid.ok()) {
      correlator = it;
      break;
    }
  }
  if (!uuid.ok()) {
    return absl::OkStatus();
  }
  // This line also checks if a metric was just read.
  auto old_timestamp =
      last_read_.CheckMetricTime(metric_name, *uuid, metric->timestamp);
  if (!old_timestamp.ok()) {
    return absl::OkStatus();
  }
  auto ms_it = measures_.find(metric_name);
  if (ms_it == measures_.end()) {
    return absl::NotFoundError("metric measure not found");
  }
  absl::StatusOr<uint64_t> val =
      GetMetric(&(metric->data), metric_desc->second.value_type);
  if (!val.ok()) {
    return val.status();
  }
  if (metric_desc->second.unit.type == MetricUnitType::kTime) {
    *val = GetUs(*val, metric_desc->second.unit.time);
  }
  if (metric_desc->second.kind == MetricKind::kCumulative) {
    *val = *val - data_memory_.StoreAndGetValue(metric_name, *uuid, *val);
  }
  auto tagMap = GetTagMap(*uuid, correlator);
  opencensus::stats::Record({{ms_it->second, *val}}, tagMap);
  return absl::OkStatus();
}

absl::Status OCGCPMetricExporter::CustomLabels(
    const absl::flat_hash_map<std::string, std::string>& labels) {
  for (auto& tag : default_tag_vector_) {
    if (labels.find(tag.first.name()) != labels.end()) {
      return absl::AlreadyExistsError(tag.first.name());
    }
  }

  for (auto& label : labels) {
    auto tag = opencensus::tags::TagKey::Register(label.first);
    default_tag_vector_.push_back(std::make_pair(tag, label.second));
  }

  default_tag_map_ =
      std::make_unique<opencensus::tags::TagMap>(default_tag_vector_);
  return absl::OkStatus();
}

void OCGCPMetricExporter::Cleanup() {
  auto uuids = last_read_.GetUUID();
  bool found;
  for (const auto& uuid : uuids) {
    found = false;
    for (auto& correlator : correlators_) {
      if (correlator->CheckUUID(uuid)) {
        found = true;
        break;
      }
    }
    if (found) continue;
    last_read_.DeleteValue(uuid);
    data_memory_.DeleteValue(uuid);
    tag_maps_.erase(uuid);
  }
}

}  // namespace ebpf_monitor
