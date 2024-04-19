FROM debian:bullseye-slim
#FROM alpine:latest

RUN apt update && apt upgrade -y && apt install -y apt-transport-https curl gnupg
RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel-archive-keyring.gpg
RUN mv bazel-archive-keyring.gpg /usr/share/keyrings
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN apt update && apt install -y git bazel-6.4.0

WORKDIR /app

COPY helloworld/cpp_client/* ./

RUN bazel-6.4.0 build :cpp_client


#WORKDIR /app

#COPY --from=0 /app/bazel-bin/cpp_client ./
CMD ["./bazel-bin/cpp_client", "--target", "server:50051", \
    "--Cert" , "/etc/secret/cpp-client-cert.pem" , "--Key", \
    "/etc/secret/cpp-client-key.pem", "--caKey", "/etc/secret/ca.pem"]
#CMD ["tail", "-f", "/dev/null"]
