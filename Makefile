# Run tests.
test:
	bash -c "set -m; bash '$(CURDIR)/scripts/test.sh'"

# Check code quality.
lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run
	npx prettier . --check

# Reformat code so it passes the code style lint checks.
format:
	go mod tidy
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --fix
	npx prettier . --write
