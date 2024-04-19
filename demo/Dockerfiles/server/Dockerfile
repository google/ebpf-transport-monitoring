FROM golang:1.20

WORKDIR /app

COPY helloworld/greeter_server/* ./

RUN go mod download
RUN go build -o main .

EXPOSE 50051

CMD ["/app/main", "-port", "50051", \
    "-Cert" , "/etc/secret/server-cert.pem" , "-Key", \
    "/etc/secret/server-key.pem", "-caKey", "/etc/secret/ca.pem"]

#CMD ["tail", "-f", "/dev/null"]
