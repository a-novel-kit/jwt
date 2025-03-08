#!/bin/bash

TEST_TOOL_PKG="gotest.tools/gotestsum@latest"

go run ${TEST_TOOL_PKG} --format pkgname -- -cover ./...
