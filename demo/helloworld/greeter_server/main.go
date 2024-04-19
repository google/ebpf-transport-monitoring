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

// Package main implements a server for Greeter service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

var (
	caKey = flag.String("caKey", "", "TLS rootCA key")
	Cert  = flag.String("Cert", "", "TLS server key")
	Key   = flag.String("Key", "", "TLS server key")
	port  = flag.Int("port", 50051, "The server port")
)

// Function to load TLS credentials from PEM files
func loadTLSCredentials(certFile, keyFile string) (*tls.Certificate, error) {
	// Read the certificate file
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate: %w", err)
	}
	return &cert, nil
}

// Function to load a CA certificate for client authentication (if needed)
func loadCACert(caFile string) (*x509.CertPool, error) {
	// Read the CA certificate file
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate: %w", err)
	}

	// Create a certificate pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA certificate to pool")
	}

	return certPool, nil
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func main() {
	flag.Parse()
	if *Cert == "" || *Key == "" || *caKey == "" {
		fmt.Printf("Need certs")
		os.Exit(2)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	cp, err := loadCACert(*caKey)
	if err != nil {
		fmt.Printf("Error loading ca cert %s", err)
		os.Exit(1)
	}
	creds, err := loadTLSCredentials(*Cert, *Key)
	if err != nil {
		fmt.Printf("Error loading credentials %s", err)
		os.Exit(1)
	}

	tlsCfg := tls.Config{}
	tlsCfg.Certificates = []tls.Certificate{*creds}
	tlsCfg.RootCAs = cp

	tlsCreds := credentials.NewTLS(&tlsCfg)

	s := grpc.NewServer(grpc.Creds(tlsCreds))
	pb.RegisterGreeterServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
