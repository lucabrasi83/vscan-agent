package main

import (
	"github.com/lucabrasi83/vscan-agent/initializer"
	"github.com/lucabrasi83/vscan-agent/scanagent"
	_ "google.golang.org/grpc/encoding/gzip"
)

func main() {

	initializer.Initialize()

	scanagent.StartServer()

}

//func (*AgentServer) SendFile(req *agentpb.FileRequest, stream agentpb.VscanAgentService_SendFileServer) error {
//
//	logging.VulscanoLog("info", "received request for Send Scan Results")
//
//	filename := req.GetRequest()
//
//	file, err := ioutil.ReadFile(filename)
//
//	if err != nil {
//
//		logging.VulscanoLog("error", "unable to open file ", err)
//	}
//
//	res := &agentpb.ScanResultsResponse{
//		ResultsJSON: file,
//	}
//
//	return stream.Send(res)
//
//}
