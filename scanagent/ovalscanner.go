package scanagent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/lucabrasi83/vscan-agent/inibuilder"
	agentpb "github.com/lucabrasi83/vscan-agent/proto"
	"github.com/lucabrasi83/vulscano/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentServer struct{}

func (*AgentServer) BuildScanConfig(req *agentpb.ScanRequest, stream agentpb.VscanAgentService_BuildScanConfigServer) error {

	logging.VulscanoLog("info", "received scan request ", req.String())

	hostname, errHost := os.Hostname()

	if errHost != nil {
		return status.Errorf(
			codes.Internal,
			fmt.Sprintln("failed to get VSCAN agent hostname"),
		)
	}

	jobID := req.GetJobId()

	if jobID == "" {
		return status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintln("job ID is missing from argument"),
		)
	}

	err := inibuilder.BuildIni(
		req.GetJobId(),
		req.GetDevices(),
		req.GetOvalSourceUrl(),
		req.SshGateway,
		req.UserDeviceCredentials,
	)

	if err != nil {
		return status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("unable to generate scan config with given arguments. error: %v\n", err),
		)
	}

	err = execScan(jobID)

	if err != nil {
		return status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("unable to execute scan. error: %v\n", err),
		)
	}

	reportDir := filepath.FromSlash("./scanjobs/" + jobID + "/reports/")

	if _, err := os.Stat(reportDir); !os.IsNotExist(err) {

		err = filepath.Walk(reportDir, func(path string, info os.FileInfo, errFileWalk error) error {

			if errFileWalk != nil {

				logging.VulscanoLog("error",
					"unable to access Joval reports directory: ", path, "error: ", errFileWalk,
				)

				return status.Errorf(
					codes.Internal,
					fmt.Sprintf("failed to send Joval JSON report stream: %v\n ", errFileWalk),
				)
			}
			if !info.IsDir() {
				reportFile, err := ioutil.ReadFile(path)

				if err != nil {
					return fmt.Errorf("error while reading report file %v: %v", path, err)
				}

				errStream := stream.Send(

					&agentpb.ScanResultsResponse{
						ScanResultsJson: reportFile,
						VscanAgentName:  hostname,
						DeviceName:      info.Name(),
					},
				)

				if errStream != nil {
					return status.Errorf(
						codes.Internal,
						fmt.Sprintf("failed to send Joval JSON report stream: %v\n ", errStream),
					)
				}
			}
			return nil
		})

		if err != nil {
			return status.Errorf(
				codes.Internal,
				fmt.Sprintf("error while looking for Joval reports directory for job ID %v\n ", jobID),
			)
		}

		return nil
	}

	return status.Errorf(
		codes.Internal,
		fmt.Sprintf("error while executing scan for job ID %v . Directory %v not found\n ", jobID, reportDir),
	)
}

func execScan(job string) error {
	cmd := exec.CommandContext(context.Background(), "java",
		"-Dlicense.file=joval/tatacommunications.com.sig.xml",
		"-jar", "joval/Joval-Utilities.jar", "scan", "-c", "scanjobs/"+job+"/config.ini",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	logFile, err := os.OpenFile("./scanjobs/"+job+"/joval_stdout.log",
		os.O_CREATE|os.O_WRONLY, 0755)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to create Joval log file for job ID ", job+" error: ", err)
	}

	defer logFile.Close()

	// Copy Joval scan output to logFile once command call exits
	defer func() {
		_, errLogFile := io.Copy(logFile, &stderr)

		if errLogFile != nil {
			logging.VulscanoLog("error",
				"failed to write log file for job ID ", job+" error: ", errLogFile)
		}
	}()

	err = cmd.Run()

	if err != nil {

		logging.VulscanoLog("error", "error while executing scan: ", err)

		return fmt.Errorf("error while executing scan %v\n", err)

	}

	return nil
}

//func (*AgentServer) BuildScanConfig(ctx context.Context, req *agentpb.ScanRequest) (*agentpb.ScanResultsResponse,
//	error) {
//
//	jobID := req.GetJobId()
//
//	if jobID == "" {
//		return nil, status.Errorf(
//			codes.InvalidArgument,
//			fmt.Sprintln("job ID is missing from argument"),
//		)
//	}
//
//	err := inibuilder.BuildIni(
//		req.GetJobId(),
//		req.GetDevices(),
//		req.GetOvalSourceUrl(),
//		req.SshGateway,
//		req.UserDeviceCredentials,
//	)
//
//	if err != nil {
//		return nil, status.Errorf(
//			codes.InvalidArgument,
//			fmt.Sprintf("unable to generate scan config with given arguments. error: %v\n", err),
//		)
//	}
//
//	cmd := exec.CommandContext(context.Background(), "java",
//		"-Dlicense.file=joval/tatacommunications.com.sig.xml",
//		"-jar", "joval/Joval-Utilities.jar", "scan", "-c", "scanjobs/"+req.GetJobId()+"/config.ini",
//	)
//
//	var stderr bytes.Buffer
//	cmd.Stderr = &stderr
//
//	logFile, err := os.OpenFile("./scanjobs/"+req.GetJobId()+"/logs/joval_stdout.log",
//		os.O_CREATE|os.O_WRONLY,
//		0755)
//
//	defer logFile.Close()
//
//	// Copy Joval scan output to logFile once command call exits
//	defer func() {
//		_, errLogFile := io.Copy(logFile, &stderr)
//
//		if errLogFile != nil {
//			logging.VulscanoLog("error",
//				"failed to write log file for job ID ", req.GetJobId()+"error: ", errLogFile)
//		}
//	}()
//
//	err = cmd.Run()
//
//	if err != nil {
//
//		logging.VulscanoLog("error", "error while executing scan: ", err)
//
//		return nil, status.Errorf(
//			codes.InvalidArgument,
//			fmt.Sprintf("error while executing scan %v\n", err),
//		)
//	}
//
//	return &agentpb.IniConfBuildResponse{
//		Ack: "OK",
//	}, nil
//
//}
