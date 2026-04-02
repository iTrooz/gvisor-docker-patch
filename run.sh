#!/usr/bin/env bash
set -euo pipefail

CGO_ENABLED=0 GO111MODULE=off go build -o ./inject-bin ./main.go
python "./main.py" --inject-bin "./inject-bin" "$@"
