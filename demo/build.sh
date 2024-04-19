set -e
#eval $(minikube docker-env)
# 
names=("go-client" "node-client" "java-client" "server" "cpp-client")

openssl genrsa -out cert-config/ca-key.pem 2048
openssl req -x509 -new -nodes -key cert-config/ca-key.pem -sha256 -days 3650 -config cert-config/ca-cert.cnf  -out cert-config/ca.pem 

# Iterate over the list
for name in "${names[@]}"; do
    docker build -f Dockerfiles/$name/Dockerfile -t $name:v1 .
    docker tag $name:v1 localhost:5000/$name
    docker push localhost:5000/$name
    openssl genrsa -out cert-config/$name-key.pem 2048
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in cert-config/$name-key.pem -out cert-config/$name-pkcs8-key.pem 
    cp cert-config/cert.cnf /tmp/config.cnf
    echo "DNS.3 = ${name}" >> "/tmp/config.cnf"
    openssl req -new -key cert-config/$name-key.pem -out cert-config/$name.csr -config /tmp/config.cnf
    openssl x509 -req -in cert-config/$name.csr -CA cert-config/ca.pem -CAkey cert-config/ca-key.pem -CAcreateserial -out cert-config/$name-cert.pem -days 365 -sha256 -extensions v3_req -extfile /tmp/config.cnf
done


