package scanagent

import (
	"context"
	"time"

	"github.com/lucabrasi83/vscan-agent/logging"
	agentpb "github.com/lucabrasi83/vscan-agent/proto"
	"golang.org/x/crypto/ssh"
)

func (*AgentServer) SSHConnectivityTest(ctx context.Context, req *agentpb.SSHGatewayTestRequest) (*agentpb.
	SSHGatewayTestResponse,
	error) {

	logging.VSCANLog("info", "Received Request to Test SSH Gateway %v", req.SshGateway.GatewayIp)

	sshAuthMethods, err := buildAuthMethods(req)

	if err != nil {
		return &agentpb.
			SSHGatewayTestResponse{
			SshTestResult: err.Error(),
			SshCanConnect: false,
		}, nil
	}

	// Build SSH Config
	sshConfig := &ssh.ClientConfig{
		User:            req.SshGateway.GatewayUsername,
		Auth:            sshAuthMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	conn, err := ssh.Dial("tcp", req.SshGateway.GatewayIp+":22", sshConfig)

	if err != nil {
		return &agentpb.
			SSHGatewayTestResponse{
			SshTestResult: err.Error(),
			SshCanConnect: false,
		}, nil
	}

	defer conn.Close()

	return &agentpb.
		SSHGatewayTestResponse{
		SshTestResult: string(conn.ServerVersion()),
		SshCanConnect: true,
	}, nil
}

func publicKey(key string) (ssh.AuthMethod, error) {

	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(signer), nil
}

func buildAuthMethods(req *agentpb.SSHGatewayTestRequest) ([]ssh.AuthMethod, error) {

	authMethod := make([]ssh.AuthMethod, 0)

	if req.SshGateway.GatewayPassword != "" {
		authMethod = append(authMethod, ssh.Password(req.SshGateway.GatewayPassword))
	}

	if req.SshGateway.GatewayPrivateKey != "" {
		keyAuth, err := publicKey(req.SshGateway.GatewayPrivateKey)

		if err != nil {
			return nil, err
		}
		authMethod = append(authMethod, keyAuth)

	}
	return authMethod, nil
}
