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

	configBuf, err := inibuilder.BuildIni(
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

	scanLogs, err := execScan(jobID, scanTimeout, stream, configBuf)

	if err != nil {
		return status.Errorf(
			codes.InvalidArgument,
			fmt.Sprintf("Agent %v - unable to execute scan. error: %v\n", hostname, err),
		)
	}

	reportDir := filepath.FromSlash("/opt/joval/scanjobs/" + jobID + "/reports/")

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
		fmt.Sprintf("agent %v - error while executing scan for job ID %v . Directory %v not found ", hostname, jobID,
			reportDir),
	)
}

func execScan(job string, t int64, stream agentpb.VscanAgentService_BuildScanConfigServer, config io.Reader) (*agentpb.
	ScanLogFileResponsePS, error) {

	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Duration(t)*time.Second)

	defer cancel()

	cmd := exec.CommandContext(ctxTimeout, "java",
		"-Dlicense.file=/opt/joval/tatacommunications.com.sig.xml",
		"-jar", "/opt/joval/Joval-Utilities.jar", "scan", "-c", "-",
	)

	cmd.Stdin = config

	// Copy Joval scan log output to logFile real-time
	// bufStream will be sent to the gRPC stream as the log lines from Joval are generated
	bufStream := bytes.NewBuffer(make([]byte, 0, 4096))

	// bufPersist will store the entire log and used for persistency in VSCAN DB
	bufPersist := new(bytes.Buffer)

	// Multiwriter will write the logs in file and buffers
	stderr := io.MultiWriter(bufStream, bufPersist)

	// Map the command Standard Error Output to the multiwriter
	cmd.Stderr = stderr

	// Semaphore channel to signal when the Cmd has finished
	done := make(chan bool)

	// Go Routine to stream the scan job logs
	go func() {
		bufTicket := time.NewTicker(500 * time.Millisecond)
		defer bufTicket.Stop()
		for {
			select {
			case <-done:
				logging.VSCANLog("info", "Joval utility exec command returned for job %s", job)
				return
			default:
				scanner := bufio.NewScanner(bufStream)

				// Initial 1KB buffer
				scannerBuf := make([]byte, 0, 1024)

				// Buffer Max Capacity 64KB
				scannerMaxCap := 64 * 1024
				scanner.Buffer(scannerBuf, scannerMaxCap)
				for scanner.Scan() {
					// Bytes returns the most recent token generated by a call to Scan.
					// The underlying array may point to data that will be overwritten by a subsequent call to Scan. It does no allocation.
					// https://stackoverflow.com/questions/58691154/bufio-scanner-goroutine-truncated-unordered-output/58691541#58691541

					//b := append([]byte(nil), scanner.Bytes()...)
					errStream := stream.Send(&agentpb.ScanResultsResponse{
						ScanLogsWebsocket: &agentpb.ScanLogFileResponseWB{ScanLogs: scanner.Bytes()},
					},
					)
					if errStream != nil {
						logging.VSCANLog("error", "Failed to read log stream for job ID %v with error %v", job, errStream)
					}

					<-bufTicket.C

				}
			}
		}

	}()
	err := cmd.Run()

	done <- true

	if err != nil {

		logging.VSCANLog("error", "Job ID %v - error while launching Joval utility: %v", job, err)

		return nil, fmt.Errorf("unable to launch Joval scan %v", err)

	}

	return &agentpb.ScanLogFileResponsePS{ScanLogs: bufPersist.Bytes()}, nil
}
