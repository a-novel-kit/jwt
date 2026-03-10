# Run tests.
test:
	bash -c "set -m; bash '$(CURDIR)/scripts/test.sh'"

# Check code quality.
lint:
	go tool -modfile=golangci-lint.mod golangci-lint run ./...
	pnpm lint

# Reformat code so it passes the code style lint checks.
format:
	go mod tidy
	go tool -modfile=golangci-lint.mod golangci-lint run ./... --fix
	pnpm format
