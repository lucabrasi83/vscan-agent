FROM golang:1.13.4-alpine as builder
RUN apk add --no-cache build-base git ca-certificates && update-ca-certificates 2>/dev/null || true
COPY . /go/src/github.com/lucabrasi83/vscan-agent
WORKDIR /go/src/github.com/lucabrasi83/vscan-agent
ENV GO111MODULE on
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -ldflags="-X github.com/lucabrasi83/vscan-agent/initializer.Commit=$(git rev-parse --short HEAD) \
    -X github.com/lucabrasi83/vscan-agent/initializer.Version=$(git describe --tags) \
    -X github.com/lucabrasi83/vscan-agent/initializer.BuiltAt=$(date +%FT%T%z) \
    -X github.com/lucabrasi83/vscan-agent/initializer.BuiltOn=$(hostname)" -o vscan-agent


FROM openjdk:13-slim
LABEL maintainer="sebastien.pouplin@tatacommunications.com"
COPY --from=builder /go/src/github.com/lucabrasi83/vscan-agent/banner.txt /opt/banner.txt
COPY --from=builder /go/src/github.com/lucabrasi83/vscan-agent/vscan-agent /opt/vscan-agent
COPY --from=builder /go/src/github.com/lucabrasi83/vscan-agent/joval /opt/joval
COPY --from=builder /go/src/github.com/lucabrasi83/vscan-agent/certs /opt/certs/
RUN chown -R 1001:1001 /opt
USER 1001
WORKDIR /opt/joval
CMD ["/opt/vscan-agent"]
