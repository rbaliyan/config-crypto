# Default recipe
default:
    @just --list

# Build all Go packages
build:
    go build ./...

# Run tests
test:
    go test ./...

# Run tests with verbose output
test-v:
    go test -v ./...

# Run tests with race detector
test-race:
    go test -race ./...

# Run tests with coverage
test-coverage:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

# Format Go code
fmt:
    go fmt ./...

# Run linter
lint:
    golangci-lint run

# Run go vet
vet:
    go vet ./...

# Run go mod tidy
tidy:
    go mod tidy

# Clean test cache and coverage files
clean:
    go clean -testcache
    rm -f coverage.out coverage.html

# Install mise tools
tools:
    mise install

# Full check: format, vet, test with race detector
check: fmt vet test-race
