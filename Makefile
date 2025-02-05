test:
	bash -c "set -m; bash '$(CURDIR)/scripts/test.sh'"

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run

format:
	go mod tidy
	go fmt ./...
	go run github.com/daixiang0/gci@latest write \
		--skip-generated \
		-s standard -s default \
		-s "prefix(github.com/a-novel-kit)" \
		-s "prefix(github.com/a-novel-kit/jwt)" \
		.
	go run mvdan.cc/gofumpt@latest -l -w .
	go run golang.org/x/tools/cmd/goimports@latest -w -local github.com/a-novel-kit .

keygen:
	go run ./internal/keys/main.go
