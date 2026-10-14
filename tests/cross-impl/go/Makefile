# The Go stock-library gate. See README.md.

VECTORS ?= ../../../vectors
GO_IMAGE ?= golang:1.26.8-alpine
REPO_ROOT := $(abspath ../../..)
# The repository path as the Docker daemon sees it. Override it when make runs
# inside a container whose paths differ from the Docker host's.
HOST_REPO_ROOT ?= $(REPO_ROOT)
# The module file that links transparency-dev/merkle v0.0.2, the latest tag,
# in place of the pinned main commit.
V002_MODFILE := go.v0.0.2.mod

export GOFLAGS ?= -buildvcs=false

.PHONY: check gate test test-v002 vet fmt-check evm-check docker-check

# Formatting, vet, the tests (including the corrupted-vector cases) against the
# pinned library and against v0.0.2, then the gate, then the EVM half of the
# anvil end-to-end vectors (evm/, its own module, with go-ethereum).
check: fmt-check vet test test-v002 gate evm-check

gate:
	go run . -vectors $(VECTORS)

test:
	go test -count=1 ./...

# The same tests linked against v0.0.2. They assert that it accepts exactly the
# five first = 0 invalid entries and agrees with the pin on everything else.
test-v002:
	go test -modfile=$(V002_MODFILE) -count=1 ./...

vet:
	go vet ./...

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed: $$out"; exit 1; fi

# evm/ is a module of its own, so go-ethereum's dependencies stay out of the
# gate module: vet, its tests (including its corrupted-vector cases), then the
# check of anchor-e2e-vectors.json. gofmt above covers its files.
evm-check:
	cd evm && go vet ./... && go test -count=1 ./... && go run . -vectors $(abspath $(VECTORS))

# The same as check, in a throwaway container, for a machine without Go. The
# repository is mounted read-only and nothing is written back to it.
docker-check:
	docker run --rm -v "$(HOST_REPO_ROOT):/src:ro" -w /src/tests/cross-impl/go \
		-e GOFLAGS=-buildvcs=false -e HOME=/tmp \
		$(GO_IMAGE) sh -c 'export GOCACHE="$$HOME/gocache" GOPATH="$$HOME/go" && test -z "$$(gofmt -l .)" && go vet ./... && go test -count=1 ./... && go test -modfile=$(V002_MODFILE) -count=1 ./... && go run . -vectors ../../../vectors && cd evm && go vet ./... && go test -count=1 ./... && go run . -vectors ../../../../vectors'
