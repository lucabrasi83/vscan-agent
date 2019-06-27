package scanagent

import (
	"net"
	"os"
	"os/signal"

	agentpb "github.com/lucabrasi83/vscan-agent/proto"
	"github.com/lucabrasi83/vulscano/logging"
	"google.golang.org/grpc"
)

// default GRPC Listening Port if not specified in environment variable
var grpcListenPort = "50051"

func StartServer() {

	if os.Getenv("VSCAN_AGENT_BIND_PORT") != "" {
		grpcListenPort = os.Getenv("VSCAN_AGENT_BIND_PORT")
	}

	lis, err := net.Listen("tcp", ":"+grpcListenPort)

	if err != nil {
		logging.VulscanoLog("fatal", "unable to open TCP socket: ", err)
	}

	s := grpc.NewServer()

	agentpb.RegisterVscanAgentServiceServer(s, &AgentServer{})

	logging.VulscanoLog("info", "starting VSCAN Agent on port 50051...")

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
