default: build

build:
	go build -v ./...

install:
	go install -v ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

# Unit tests run the provider against an in-process fake Permio API. They need a terraform binary on PATH
# or in TF_ACC_TERRAFORM_PATH.
test:
	go test -race -count=1 ./...

# Acceptance tests run against a real Permio API and create (then destroy) real objects.
# Requires PERMIO_API_KEY (full access); optionally PERMIO_API_URL and PERMIO_PROJECT.
testacc:
	TF_ACC=1 go test -count=1 -run TestAcc -v -timeout 30m ./internal/provider/

docs:
	go generate ./...

fmt:
	gofmt -w .
	terraform fmt -recursive examples

.PHONY: default build install lint test testacc docs fmt
