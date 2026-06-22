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

# Run all tests (core module includes all KMS provider packages)
test-all:
    go test -race ./...

# Run the fast smoke subset: must-work happy paths and runnable examples
smoke:
    go test -run '^TestSmoke|^Example' -timeout 60s ./...

# Run benchmarks with allocation stats, 10 runs, saving output for benchstat
bench:
    go test -run '^$' -bench=. -benchmem -count=10 ./... | tee bench.txt

# Compare two benchmark runs with benchstat (install: go install golang.org/x/perf/cmd/benchstat@latest)
bench-compare old="old.txt" new="new.txt":
    benchstat {{old}} {{new}}

# Full check: format, vet, test with race detector
check: fmt vet test-race

# Run vulnerability check
vulncheck:
    go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Check for outdated dependencies
depcheck:
    go list -m -u all | grep '\[' || echo "All dependencies are up to date"

# Create and push a new release tag (bumps patch version)
release:
    ./scripts/release.sh
