package scanagent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

const (
	jovalStdOutLogFile = "joval_stdout.log"
)

func init() {

	hostname, errHost = os.Hostname()

	if errHost != nil {
		logging.VSCANLog("fatal", "failed to get local VSCAN agent hostname: %v", errHost)
	}

}
func (*AgentServer) BuildScanConfig(req *agentpb.ScanRequest, stream agentpb.VscanAgentService_BuildScanConfigServer) error {

	logging.VSCANLog("info",
		"Received scan request: Job ID %v - Target Device(s): %v - Requested Timeout (sec): %d\n",
		req.GetJobId(), req.GetDevices(), req.GetScanTimeoutSeconds(),
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

	scanLogs, err := execScan(jobID, scanTimeout, stream)

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

				logging.VSCANLog("error",
					"unable to access Joval reports directory: %v with error %v", path, errFileWalk,
				)

				return status.Errorf(
					codes.Internal,
					fmt.Sprintf("agent %v - failed to send Joval JSON report stream: %v", hostname, errFileWalk),
				)
			}
			if !info.IsDir() {
				reportFile, err := ioutil.ReadFile(path)

				if err != nil {
					return fmt.Errorf("agent %v - error while reading report file %v: %v", hostname, path, err)
				}

				errStream := stream.Send(

					&agentpb.ScanResultsResponse{
						ScanResultsJson: reportFile,
						VscanAgentName:  hostname,
						DeviceName:      info.Name(),
						ScanLogsPersist: scanLogs,
					},
				)

				if errStream != nil {
					return status.Errorf(
						codes.Internal,
						fmt.Sprintf("agent %v - failed to send Joval JSON report stream: %v", hostname, errStream),
					)
				}
			}
			return nil
		})

		if err != nil {
			return status.Errorf(
				codes.Internal,
				fmt.Sprintf("agent %v - error while looking for Joval reports directory for job ID %v",
					hostname, jobID),
			)
		}

		return nil
	}

	return status.Errorf(
		codes.Internal,
		fmt.Sprintf("agent %v - error while executing scan for job ID %v . Directory %v not found", hostname, jobID,
			reportDir),
	)
}

func execScan(job string, t int64, stream agentpb.VscanAgentService_BuildScanConfigServer) (*agentpb.
	ScanLogFileResponsePS, error) {

	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Duration(t)*time.Second)

	defer cancel()

	cmd := exec.CommandContext(ctxTimeout, "java",
		"-Dlicense.file=joval/tatacommunications.com.sig.xml",
		"-jar", "joval/Joval-Utilities.jar", "scan", "-c", "scanjobs/"+job+"/config.ini",
	)

	// Build File Path using join for efficiency
	filePath := strings.Join([]string{".", "scanjobs", job, jovalStdOutLogFile}, "/")

	logFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0755)

	if err != nil {
		logging.VSCANLog("error",
			"failed to create Joval log file for job ID %v with error %v", job, err)
	}

	defer func() {

		errFileClose := logFile.Close()

		if errFileClose != nil {
			logging.VSCANLog("error",
				"failed to close Joval log file for job ID %v with error %v", job, errFileClose)
		}
	}()

	// Copy Joval scan log output to logFile real-time
	// bufStream will be sent to the gRPC stream as the log lines from Joval are generated
	bufStream := new(bytes.Buffer)

	// bufPersist will store the entire log and used for persistency in VSCAN DB
	bufPersist := new(bytes.Buffer)

	// Multiwriter will write the logs in file and buffers
	stderr := io.MultiWriter(logFile, bufStream, bufPersist)

	// Map the command Standard Error Output to the multiwriter
	cmd.Stderr = stderr

	// Semaphore channel to signal when the Cmd has finished
	done := make(chan bool)

	// Go Routine to stream the scan job logs
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				scanner := bufio.NewScanner(bufStream)
				for scanner.Scan() {
					time.Sleep(1 * time.Second)
					_ = stream.Send(&agentpb.ScanResultsResponse{
						ScanLogsWebsocket: &agentpb.ScanLogFileResponseWB{ScanLogs: scanner.Bytes()},
					},
					)
				}

			}
		}

	}()
	err = cmd.Run()

	done <- true

	if err != nil {

		logging.VSCANLog("error", "Job ID %v - error while launching Joval utility: %v", job, err)

		return nil, fmt.Errorf("unable to launch Joval scan %v", err)

	}

	return &agentpb.ScanLogFileResponsePS{ScanLogs: bufPersist.Bytes()}, nil
}
