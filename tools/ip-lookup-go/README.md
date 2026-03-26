# ip-lookup (Go)

High-concurrency IP lookup utility for PTR + ASN/Organisation enrichment.

## Build

Quick build (Linux + Windows):

```bash
cd tools/ip-lookup-go
./build.sh
```

Manual Linux build:

```bash
cd tools/ip-lookup-go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ip-lookup .
```

Manual Windows cross-compile (from Linux):

```bash
cd tools/ip-lookup-go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ip-lookup.exe .
```

## Usage

Single target:

```bash
./ip-lookup --ip 8.8.8.8
```

Batch from file:

```bash
./ip-lookup --file ips.txt --workers 50
```

JSON output:

```bash
./ip-lookup --file ips.txt --workers 50 --json
```
