set -e

names=("go-client" "node-client" "java-client" "server" "cpp-client")

for name in "${names[@]}"; do
    kubectl delete secret $name-secret
    kubectl create secret generic $name-secret --from-file=cert-config/$name-key.pem --from-file=cert-config/$name-pkcs8-key.pem --from-file=cert-config/$name-cert.pem  --from-file=cert-config/ca.pem
done
