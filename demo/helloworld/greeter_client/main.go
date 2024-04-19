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

// Package main implements a client for Greeter service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

const (
	defaultName = "world"
)

var (
	caKey = flag.String("caKey", "", "TLS rootCA key")
	Cert  = flag.String("Cert", "", "TLS server cert")
	Key   = flag.String("Key", "", "TLS server key")
	addr  = flag.String("target", "localhost:50051", "the address to connect to")
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

func main() {
	flag.Parse()
	// Set up a connection to the server.
	cp, err := loadCACert(*caKey)
	if err != nil {
		fmt.Errorf("Error loading ca cert %s", err)
		os.Exit(1)
	}
	creds, err := loadTLSCredentials(*Cert, *Key)
	if err != nil {
		fmt.Errorf("Error loading credentials %s", err)
		os.Exit(1)
	}

	tlsCfg := tls.Config{}
	tlsCfg.Certificates = []tls.Certificate{*creds}
	tlsCfg.RootCAs = cp

	tlsCreds := credentials.NewTLS(&tlsCfg)

	for true {
		func() {
			conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(tlsCreds))
			if err != nil {
				log.Fatalf("did not connect: %v", err)
			}
			c := pb.NewGreeterClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
			defer cancel()
			for i := 1; i <= 180; i++ {
				r, err := c.SayHello(ctx, &pb.HelloRequest{Name: strconv.Itoa(i)})
				if err != nil {
					log.Fatalf("could not greet: %v", err)
				}
				time.Sleep(time.Second)

				log.Printf("Greeting: %s", r.GetMessage())
			}
			conn.Close()
		}()
	}
}
