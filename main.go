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
