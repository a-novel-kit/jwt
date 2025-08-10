# Define tool versions.
GCI="github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.3.1"

# Run tests.
test:
	bash -c "set -m; bash '$(CURDIR)/scripts/test.sh'"

# Check code quality.
lint:
	go run ${GCI} run
	npx prettier . --check

# Reformat code so it passes the code style lint checks.
format:
	go mod tidy
	go run ${GCI} run --fix
	npx prettier . --write
