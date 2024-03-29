package scanagent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/lucabrasi83/vscan-agent/logging"
	"github.com/lucabrasi83/vscan-agent/middleware"
	agentpb "github.com/lucabrasi83/vscan-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// default GRPC Listening Port if not specified in environment variable
var grpcListenPort = "50051"

const (
	certFile   = "/opt/certs/vscan-agent.pem"
	keyFile    = "/opt/certs/vscan-agent.key"
	caCertFile = "/opt/certs/TCL-ENT-CA.pem"
)

func StartServer() {

	if os.Getenv("VSCAN_AGENT_BIND_PORT") != "" {
		grpcListenPort = os.Getenv("VSCAN_AGENT_BIND_PORT")
	}

	lis, err := net.Listen("tcp", ":"+grpcListenPort)

	if err != nil {
		logging.VSCANLog("fatal", "unable to open TCP socket: %v", err)
	}

	tlsCredentials, err := serverCertLoad()

	if err != nil {
		logging.VSCANLog("fatal", "unable to load TLS certificates: %v", err)
	}

	limiter := middleware.AlwaysPassLimiter{}

	s := grpc.NewServer(
		grpc.Creds(tlsCredentials),
		grpc_middleware.WithUnaryServerChain(
			middleware.UnaryServerInterceptor(&limiter),
		),
		grpc_middleware.WithStreamServerChain(
			middleware.StreamServerInterceptor(&limiter),
		),
	)

	agentpb.RegisterVscanAgentServiceServer(s, &AgentServer{})

	logging.VSCANLog("info", "starting VSCAN Agent on port %v...\n", grpcListenPort)

	// Channel to handle graceful shutdown of GRPC Server
	ch := make(chan os.Signal, 1)

	// Write in Channel in case of OS request to shut process
	signal.Notify(ch, os.Interrupt)

	go func() {
		if err := s.Serve(lis); err != nil {
			logging.VSCANLog("fatal", "unable to start GRPC server: %v", err)
		}
	}()

	// Block main function from exiting until ch receives value
	<-ch
	logging.VSCANLog("info", "Gracefully shutting down VSCAN Agent...")

	// Stop GRPC server and TCP listener
	s.GracefulStop()
	lis.Close()
}

// serverCertLoad will load the TLS certificates for the gRPC server
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
