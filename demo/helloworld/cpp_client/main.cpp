/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "grpc/grpc_security.h"
#include "grpcpp/security/credentials.h"
#include "grpcpp/security/tls_credentials_options.h"
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/grpcpp.h>

#include "helloworld.grpc.pb.h"


ABSL_FLAG(std::string, caKey, "",
          "PEM file storing a root certificate");
ABSL_FLAG(std::string, Cert, "",
          "PEM file storing a client certificate");
ABSL_FLAG(std::string, Key, "",
          "PEM file storing a client private key");
ABSL_FLAG(std::string, target, "localhost:50051", "Server address");

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

std::string ReadFile(const std::string &path) {
  std::string data;
  FILE *f = fopen(path.c_str(), "r");
  if (f == nullptr) {
    std::cerr << "file not found" << path;
    exit(1);
  }
  char buf[1024];
  for (;;) {
    ssize_t n = fread(buf, 1, sizeof(buf), f);
    if (n <= 0)
      break;
    data.append(buf, n);
  }
  if (ferror(f)) {
    std::cerr << "read error" << path;
    exit(1);
  }
  fclose(f);
  return data;
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  std::string rootCaFile = absl::GetFlag(FLAGS_caKey);
  std::string clientCertFile = absl::GetFlag(FLAGS_Cert);
  std::string clientKeyFile = absl::GetFlag(FLAGS_Key);

  if (rootCaFile.empty() || clientCertFile.empty() || clientKeyFile.empty()){
    std::cerr << "Invalid paths" << std::endl;
    exit(0);
  }

  const auto root_ca = ReadFile(rootCaFile);
  const auto client_cert = ReadFile(clientCertFile);
  const auto client_key = ReadFile(clientKeyFile);

  grpc::experimental::IdentityKeyCertPair key_cert_pair;
  key_cert_pair.private_key = client_key;
  key_cert_pair.certificate_chain = client_cert;
  std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs;
  identity_key_cert_pairs.emplace_back(key_cert_pair);

  auto certificate_provider = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
        root_ca, identity_key_cert_pairs);
      

  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(std::move(certificate_provider));
  options.set_verify_server_certs(false);
  auto channel_creds = grpc::experimental::TlsCredentials(options);
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.
  std::string target_str = absl::GetFlag(FLAGS_target);
  // We indicate that the channel isn't authenticated (use of
  // InsecureChannelCredentials()).
  while (1) {
  GreeterClient greeter(
      grpc::CreateChannel(target_str, channel_creds));
      for (int i =0; i< 1800; i++){
        std::string reply = greeter.SayHello(std::to_string(i));
	std::cout << reply << std::endl;
       	usleep(100000);
      }
  }
  return 0;
}
