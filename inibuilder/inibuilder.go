package inibuilder

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ini/ini"
	"github.com/lucabrasi83/vscan-agent/logging"
	agentpb "github.com/lucabrasi83/vscan-agent/proto"
)

// Skeleton Struct to reflect from config.ini
type Skeleton struct {
	Benchmark
	Logs
}

// Benchmark Section Struct in config.ini
type Benchmark struct {
	Profile      string `ini:"profile"`
	Source       string `ini:"source"`
	XccdfID      string `ini:"xccdf_id"`
	XccdfVersion int    `ini:"xccdf_version"`
}

// Logs Section Struct in config.ini
type Logs struct {
	ExportDir       string `ini:"export.dir"`
	Level           string `ini:"level"`
	OutputExtension string `ini:"output.extension"`
}

// BuildIni generates config.ini file per scan jobs.
// The config.ini file is placed in tmp/<scan-job-id>/ folder by default
// It returns any error encountered during the config.ini file generation
func BuildIni(jobID string, dev []*agentpb.Device, jovalSource string, sshGW *agentpb.SSHGateway,
	creds *agentpb.UserDeviceCredentials) (reader io.Reader, err error) {

	// Starts with baseline ini file
	cfg, err := ini.Load(
		[]byte(
			`[Report: JSON]
		input.type = xccdf_results
		output.extension = json 
		transform.file =` + filepath.FromSlash(
				"./tools/arf_xccdf_results_to_json_events.xsl")))

	if err != nil {
		return nil, fmt.Errorf("error while loading default ini content for job ID %v: %v", jobID, err)
	}

	// Add Device Credentials sections details
	var credsName string
	if creds.GetCredentialsName() != "" {

		credsName = creds.GetCredentialsName()
		err = buildDeviceCredentialsSections(cfg, creds)

		if err != nil {
			return nil, err
		}
	}

	// Add SSH Gateway sections details if a gateway is specified to UserSSHGateway is not nil
	var sshGWName string
	if sshGW.GetGatewayName() != "" {

		sshGWName = sshGW.GetGatewayName()
		err = buildSSHGatewaySections(cfg, sshGW)

		if err != nil {
			return nil, err
		}

	}

	secSkeleton := &Skeleton{
		Benchmark{
			Profile:      "xccdf_org.joval_profile_all_rules",
			Source:       jovalSource,
			XccdfID:      "xccdf_org.joval_benchmark_generated",
			XccdfVersion: 0,
		},
		Logs{
			ExportDir:       filepath.FromSlash("./scanjobs/" + jobID + "/logs"),
			Level:           "off",
			OutputExtension: ".log",
		},
	}

	if err = cfg.ReflectFrom(secSkeleton); err != nil {
		return nil, fmt.Errorf("error while reflecting struct into config.ini: %v", err)
	}

	// Continue INI building in separate function for dynamic parameters
	if err = dynaIniGen(cfg, jobID, dev, sshGWName, credsName); err != nil {
		return nil, fmt.Errorf("error while generating dynamic parameters for config.ini: %v", err)
	}

	// Assigns directory name per scan job ID
	dir := filepath.FromSlash("./scanjobs/" + jobID)

	// Check whether the directory to be created already exists. If not, we create it with Unix permission 0750
	if _, errDirNotExist := os.Stat(dir); os.IsNotExist(errDirNotExist) {
		if errCreateDir := os.MkdirAll(dir, 0750); errCreateDir != nil {
			return nil, fmt.Errorf("error while creating directory for job ID %v: %v", jobID, errCreateDir)
		}
	}

	configBuf := &bytes.Buffer{}
	_, errBuf := cfg.WriteTo(configBuf)
	if errBuf != nil {
		return nil, errBuf
	}
	configBuf.WriteString("#EOF")

	logging.VSCANLog("warning", "%v", configBuf.Cap())

	return configBuf, nil
}

func buildSSHGatewaySections(cfg *ini.File, sshGW *agentpb.SSHGateway) error {

	sshGWCredSec, err := cfg.NewSection("Credential: " + "ssh-gateway")

	if err != nil {
		return fmt.Errorf("error while setting SSH gateway credentials section in config.ini: %v ", err)
	}

	_, err = sshGWCredSec.NewKey("type", "SSH")

	if err != nil {
		return fmt.Errorf("error while setting SSH gateway credentials type key in config.ini: %v ", err)
	}
	_, err = sshGWCredSec.NewKey("username", sshGW.GetGatewayUsername())

	if err != nil {
		return fmt.Errorf("error while setting SSH gateway username key in config.ini: %v ", err)
	}

	if sshGW.GatewayPassword != "" {
		_, err = sshGWCredSec.NewKey("password", sshGW.GetGatewayPassword())

		if err != nil {
			return fmt.Errorf("error while setting SSH gateway password key in config.ini: %v ", err)
		}
	}

	if sshGW.GatewayPrivateKey != "" {

		// Format SSH Private Key to comply with Joval ini format
		pvKeyJovalFormat := strings.Replace(sshGW.GetGatewayPrivateKey(), "\n", "\\\r", -1)

		_, err := sshGWCredSec.NewKey("private_key", pvKeyJovalFormat)

		if err != nil {
			return fmt.Errorf("error while setting SSH gateway private key in config.ini: %v ", err)
		}

		logging.VSCANLog("warning", "%v", pvKeyJovalFormat)

	}

	sshGwSec, err := cfg.NewSection("Gateway: " + sshGW.GetGatewayName())

	if err != nil {
		return fmt.Errorf("error while setting SSH sateway section in config.ini: %v ", err)
	}

	_, err = sshGwSec.NewKey("host", sshGW.GetGatewayIp())

	if err != nil {
		return fmt.Errorf("error while setting SSH gateway IP key in config.ini: %v ", err)
	}

	_, err = sshGwSec.NewKey("credential", "ssh-gateway")

	if err != nil {
		return fmt.Errorf("error while setting SSH gateway credentials key in config.ini: %v ", err)
	}

	return nil

}

func buildDeviceCredentialsSections(cfg *ini.File, creds *agentpb.UserDeviceCredentials) error {

	deviceCredSec, err := cfg.NewSection("Credential: " + creds.GetCredentialsName())

	if err != nil {
		return fmt.Errorf("error while setting SSH device credentials section in config.ini: %v ", err)
	}

	_, err = deviceCredSec.NewKey("type", "SSH")

	if err != nil {
		return fmt.Errorf("error while setting SSH device credentials type key in config.ini: %v ", err)
	}
	_, err = deviceCredSec.NewKey("username", creds.GetUsername())

	if err != nil {
		return fmt.Errorf("error while setting SSH device username key in config.ini: %v ", err)
	}

	if creds.Password != "" {
		_, err = deviceCredSec.NewKey("password", creds.GetPassword())

		if err != nil {
			return fmt.Errorf("error while setting SSH device password key in config.ini: %v ", err)
		}
	}

	if creds.CredentialsDeviceVendor == "CISCO" && creds.GetIosEnablePassword() != "" {
		_, err = deviceCredSec.NewKey("ios_enable_password", creds.GetIosEnablePassword())

		if err != nil {
			return fmt.Errorf("error while setting SSH device IOS enable password key in config.ini: %v ", err)
		}
	}

	if creds.PrivateKey != "" {

		// Format SSH Private Key to comply with Joval ini format
		pvKeyJovalFormat := strings.Replace(creds.GetPrivateKey(), "\n", "\\\r", -1)

		_, err := deviceCredSec.NewKey("private_key", pvKeyJovalFormat)

		if err != nil {
			return fmt.Errorf("error when setting SSH device private key in config.ini: %v ", err)
		}

	}

	return nil

}

// dynaIniGen generates the remainder of the config.ini file for dynamic sections and key/value pairs
func dynaIniGen(cfg *ini.File, jobID string, dev []*agentpb.Device, sshGWName string, credsName string) error {

	_, err := cfg.Section(
		"Report: JSON").NewKey("export.dir", filepath.FromSlash("./scanjobs/"+jobID+"/reports"))

	if err != nil {
		return fmt.Errorf("error while setting reports directory in config.ini: %v ", err)
	}
	// Loop through devices slice to access the map and build config.ini [Target] section(s)
	for _, d := range dev {
		devSection, err := cfg.NewSection("Target: " + d.GetDeviceName())

		if err != nil {
			return fmt.Errorf("error while setting device section in config.ini: %v ", err)
		}
		_, err = devSection.NewKey("credential", credsName)

		if err != nil {
			return fmt.Errorf("error while setting credential key in config.ini: %v ", err)
		}
		_, err = devSection.NewKey("host", d.GetIpAddress())

		if err != nil {
			return fmt.Errorf("error while setting host key in config.ini: %v ", err)
		}

		// Add SSH Gateway Name if not empty string
		if sshGWName != "" {
			_, err = devSection.NewKey("gateway", sshGWName)

			if err != nil {
				return fmt.Errorf("error while setting gateway key in config.ini: %v ", err)
			}
		}
	}

	return nil

}
