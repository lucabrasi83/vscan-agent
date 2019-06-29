package scanagent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"

	"github.com/lucabrasi83/vscan-agent/logging"
	agentpb "github.com/lucabrasi83/vscan-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// default GRPC Listening Port if not specified in environment variable
var grpcListenPort = "50051"

const (
	certFile   = "./certs/vscan-agent.pem"
	keyFile    = "./certs/vscan-agent.key"
	caCertFile = "./certs/TCL-ENT-CA.pem"
)

func StartServer() {

	if os.Getenv("VSCAN_AGENT_BIND_PORT") != "" {
		grpcListenPort = os.Getenv("VSCAN_AGENT_BIND_PORT")
	}

	lis, err := net.Listen("tcp", ":"+grpcListenPort)

	if err != nil {
		logging.VulscanoLog("fatal", "unable to open TCP socket: ", err)
	}

	tlsCredentials, err := serverCertLoad()

	if err != nil {
		logging.VulscanoLog("fatal", "unable to load TLS certificates: ", err)
	}

	s := grpc.NewServer(grpc.Creds(tlsCredentials))

	agentpb.RegisterVscanAgentServiceServer(s, &AgentServer{})

	logging.VulscanoLog("info", fmt.Sprintf("starting VSCAN Agent on port %v...\n", grpcListenPort))

	// Channel to handle graceful shutdown of GRPC Server
	ch := make(chan os.Signal, 1)

	// Write in Channel in case of OS request to shut process
	signal.Notify(ch, os.Interrupt)

	go func() {
		if err := s.Serve(lis); err != nil {
			logging.VulscanoLog("fatal", "unable to start GRPC server: ", err)
		}
	}()

	// Block main function from exiting until ch receives value
	<-ch
	logging.VulscanoLog("info", "Gracefully shutting down VSCAN Agent...")

	// Stop GRPC server and TCP listener
	s.GracefulStop()
	lis.Close()
}

func serverCertLoad() (credentials.TransportCredentials, error) {

	// Load the certificates from disk
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)

	if err != nil {
		return nil, fmt.Errorf("error while loading VSCAN agent server certificate: %v", err)
	}

	// Create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()

	ca, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("error while loading VSCAN agent root Certificate Authority: %v", err)
	}

	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, fmt.Errorf("failed to append Root CA %v certs", ca)
	}

	return credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}), nil

}
