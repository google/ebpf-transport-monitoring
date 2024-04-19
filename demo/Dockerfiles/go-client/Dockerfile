FROM golang:1.20

WORKDIR /app

COPY helloworld/greeter_client/* ./

RUN go mod download
RUN go build -o main .

CMD ["/app/main", "-target", "server:50051", \
    "-Cert" , "/etc/secret/go-client-cert.pem" , "-Key", \
    "/etc/secret/go-client-key.pem", "-caKey", "/etc/secret/ca.pem"]

#CMD ["tail", "-f", "/dev/null"]
