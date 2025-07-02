# Run tests.
test:
	bash -c "set -m; bash '$(CURDIR)/scripts/test.sh'"

# Check code quality.
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.2.1 run
	npx prettier . --check

# Reformat code so it passes the code style lint checks.
format:
	go mod tidy
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.2.1 run --fix
	npx prettier . --write
