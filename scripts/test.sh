#!/bin/bash

TEST_TOOL_PKG="gotest.tools/gotestsum@latest"

# First, we set up a temporary directory to receive the coverage (binary) files...
GOCOVERTMPDIR="$(mktemp -d)"
trap 'rm -rf -- "$GOCOVERTMPDIR"' EXIT

# Execute tests.
#
# Go list has 2 exclusive commands, that only work for a specified use case:
# - `go list -m`: list modules (in workspace)
# - `go list ./...`: list sub packages
#
# Since we need a solution to accommodate both cases, I used a workaround;
#  - `go list -m` starts by listing every module (usually just one when not working with workspaces)
#  - `go list ${mod//$(go list .)/.}/...; done)` list every package inside a given sub module
#    - `go list ${package_list}` will print warnings when provided symlinks, which makes the output unusable (until
#       its sanitized). To resolve this issue, we just edit out the prefix for each module (which normally equals the
#       root module name), to turn those modules into relative paths.
#       eg:
#         github.com/org/repo -> .
#         github.com/org/repo/submodule -> ./submodule
go run ${TEST_TOOL_PKG} --format pkgname -- \
  -cover -covermode=atomic -v -count=1 \
  $(for mod in $(go list -m); do go list ${mod//$(go list .)/.}/...; done) \
  -args -test.gocoverdir=$GOCOVERTMPDIR

# Collect test coverage.
go tool covdata textfmt -i="$GOCOVERTMPDIR" -o=cover.out
go tool cover -html=cover.out -o=cover.html
