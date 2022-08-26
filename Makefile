.DEFAULT_GOAL := build

GO_BIN=${HOME}/go/go1.16.15/bin/go
EXECUTABLE=sfpFlattener

all: test vet fmt lint build

test:
	echo "Test"
	${GO_BIN} test ./cmd/

vet:
	echo "Vet"
	${GO_BIN} vet ./cmd/

fmt:
	echo "Fmt"
	${GO_BIN} list -f '{{.Dir}}' ./... | grep -v /vendor/ | xargs -L1 gofmt -l
	test -z $$(${GO_BIN} list -f '{{.Dir}}' ./... | grep -v /vendor/ | xargs -L1 gofmt -l)

lint:
	echo "Linting"
	${GO_BIN} list -f '{{.Dir}}' ./... | grep -v /vendor/ | xargs -L1 golint -set_exit_status

build:
	echo "Compiling for every OS and Platform"
	#GOOS=freebsd GOARCH=amd64 ${GO_BIN} build -o bin/${EXECUTABLE}-freebsd-amd64 ./main.go
	GOOS=darwin GOARCH=arm64 ${GO_BIN} build -o bin/${EXECUTABLE}-macos-arm64 ./main.go
	GOOS=darwin GOARCH=amd64 ${GO_BIN} build -o bin/${EXECUTABLE}-macos-amd64 ./main.go
	GOOS=linux GOARCH=amd64 ${GO_BIN} build -o bin/${EXECUTABLE}-linux-amd64 ./main.go
	GOOS=windows GOARCH=amd64 ${GO_BIN} build -o bin/${EXECUTABLE}-windows-amd64.exe ./main.go

	echo "Making sure all binaries are executable"
	chmod +x ./bin/*