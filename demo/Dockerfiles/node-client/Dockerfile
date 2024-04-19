FROM node:21-alpine3.18

WORKDIR /app

COPY helloworld/node_client/* ./
COPY helloworld/helloworld/helloworld.proto ./

RUN npm install
RUN npm install @grpc/grpc-js

CMD ["node", "greeter_client.js", "--target", "server:50051", \
    "--Cert" , "/etc/secret/node-client-cert.pem" , "--Key", \
    "/etc/secret/node-client-key.pem", "--caKey", "/etc/secret/ca.pem"]
