.PHONY: all get test clean build cover

GO ?= go
BIN_NAME=ssh-vault
VERSION=$(shell git describe --tags --always)

all: clean build

get:
	${GO} get

build: get
	${GO} build -ldflags "-X main.version=${VERSION}" -o ${BIN_NAME} cmd/ssh-vault/main.go;

clean:
	@rm -rf ${BIN_NAME} ${BIN_NAME}.debug *.out build debian

test: get
	${GO} test -race -v

cover:
	${GO} test -cover && \
	${GO} test -coverprofile=coverage.out  && \
	${GO} tool cover -html=coverage.out
