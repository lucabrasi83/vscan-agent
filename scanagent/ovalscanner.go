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
	"time"

	"github.com/lucabrasi83/vscan-agent/inibuilder"
	"github.com/lucabrasi83/vscan-agent/logging"
	agentpb "github.com/lucabrasi83/vscan-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentServer struct{}

var (
	hostname string
	errHost  error
)

func init() {

	hostname, errHost = os.Hostname()

	if errHost != nil {
		logging.VulscanoLog("fatal", fmt.Sprintf("failed to get local VSCAN agent hostname: %v\n", errHost))
	}

}
func (*AgentServer) BuildScanConfig(req *agentpb.ScanRequest, stream agentpb.VscanAgentService_BuildScanConfigServer) error {

	logging.VulscanoLog("info",
		fmt.Sprintf("Received scan request: Job ID %v - Target Device(s): %v - Requested Timeout (sec): %d\n",
			req.GetJobId(), req.GetDevices(), req.GetScanTimeoutSeconds()),
	)

	jobID := req.GetJobId()

	scanTimeout := req.GetScanTimeoutSeconds()

	if jobID == "" {
		return status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("Agent %v - job ID is missing from argument\n", hostname),
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
			fmt.Sprintf("Agent %v - unable to generate scan config with given arguments. error: %v\n", hostname, err),
		)
	}

	err = execScan(jobID, scanTimeout)

	if err != nil {
		return status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("Agent %v - unable to execute scan. error: %v\n", hostname, err),
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
					fmt.Sprintf("Agent %v - failed to send Joval JSON report stream: %v\n ", hostname, errFileWalk),
				)
			}
			if !info.IsDir() {
				reportFile, err := ioutil.ReadFile(path)

				if err != nil {
					return fmt.Errorf("Agent %v - error while reading report file %v: %v\n", hostname, path, err)
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
						fmt.Sprintf("Agent %v - failed to send Joval JSON report stream: %v\n ", hostname, errStream),
					)
				}
			}
			return nil
		})

		if err != nil {
			return status.Errorf(
				codes.Internal,
				fmt.Sprintf("Agent %v - error while looking for Joval reports directory for job ID %v\n ",
					hostname, jobID),
			)
		}

		return nil
	}

	return status.Errorf(
		codes.Internal,
		fmt.Sprintf("Agent %v - error while executing scan for job ID %v . Directory %v not found\n ", hostname, jobID,
			reportDir),
	)
}

func execScan(job string, t int64) error {

	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Duration(t)*time.Second)

	defer cancel()

	cmd := exec.CommandContext(ctxTimeout, "java",
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

		logging.VulscanoLog("error", fmt.Sprintf("Job ID %v - error while launching Joval utility: %v\n", job, err))

		return fmt.Errorf("unable to launch Joval scan %v\n", err)

	}

	return nil
}
