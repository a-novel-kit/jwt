#!/bin/bash

# Run every package's tests with coverage; -count=1 bypasses the Go test cache so each run executes.
go tool -modfile=gotestsum.mod gotestsum --format pkgname -- -count=1 -cover ./...
