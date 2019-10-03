package middleware

import (
	"context"
	"os"
	"runtime"
	"strconv"

	"github.com/lucabrasi83/vscan-agent/logging"
	"github.com/shirou/gopsutil/load"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	hostname string
	errHost  error
)

// maxLoadLimit represents the threshold at which we abort the Request due to high system load
// By default value is set at 90% for 5 minutes Average Load
const maxLoadLimit = 0.9

func init() {

	hostname, errHost = os.Hostname()

	if errHost != nil {
		logging.VSCANLog("fatal", "failed to get local VSCAN agent hostname: %v\n", errHost)
	}

}

// alwaysPassLimiter is an example limiter which impletemts Limiter interface.
// It does not limit any request because Limit function always returns false.
type AlwaysPassLimiter struct{}

// Limiter defines the interface to perform request rate limiting.
// If Limit function return true, the request will be rejected.
// Otherwise, the request will pass.
type Limiter interface {
	Limit() bool
}

// UnaryServerInterceptor returns a new unary server interceptors that performs request rate limiting.
func UnaryServerInterceptor(limiter Limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if limiter.Limit() {
			return nil, status.Errorf(codes.ResourceExhausted,
				"request is rejected by agent %v due to rate limiting policy", hostname)
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a new stream server interceptor that performs rate limiting on the request.
func StreamServerInterceptor(limiter Limiter) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if limiter.Limit() {
			return status.Errorf(codes.ResourceExhausted,
				"request is rejected by agent %v due to rate limiting policy", hostname)
		}
		return handler(srv, stream)
	}
}

func (*AlwaysPassLimiter) Limit() bool {

	// Number of CPU cores available
	numCPU := runtime.NumCPU()

	// System Load averages for 1 minute, 5 minutes, 15 minutes
	maxLoadAverages, _ := load.Avg()

	// Current 5 minutes System Load Average
	currentLoad := maxLoadAverages.Load5

	// Maximum Load tolerated below must be below 0.9
	maxLoad := currentLoad / float64(numCPU)

	if maxLoad >= maxLoadLimit {
		logging.VSCANLog("error",
			"Request rejected due to high system load. Current 5 minutes Average System Load at %v",
			strconv.FormatFloat(currentLoad, 'f', 2, 64),
		)

		return true
	}
	return false
}
