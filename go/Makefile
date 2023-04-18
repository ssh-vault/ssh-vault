.PHONY: all get test clean build cover compile goxc bintray

GO ?= go
BIN_NAME=ssh-vault
GO_XC = ${GOPATH}/bin/goxc -os="freebsd netbsd openbsd darwin linux windows" -bc="!386"
GOXC_FILE = .goxc.json
GOXC_FILE_LOCAL = .goxc.local.json
VERSION=$(shell git describe --tags --always)

all: clean build

get:
	${GO} mod tidy

build: get
	${GO} build -ldflags "-s -w -X main.version=${VERSION}" -o ${BIN_NAME} cmd/ssh-vault/main.go;

build-linux:
	for arch in amd64 arm64; do \
		mkdir -p build/$${arch}; \
		GOOS=linux GOARCH=$${arch} ${GO} build -ldflags "-s -w -X main.version=${VERSION}" -o build/$${arch}/${BIN_NAME} cmd/ssh-vault/main.go; \
	done

clean:
	@rm -rf ssh-vault-* ${BIN_NAME} ${BIN_NAME}.debug *.out build debian

test: get
	${GO} test -race -v

cover:
	${GO} test -cover && \
	${GO} test -coverprofile=coverage.out  && \
	${GO} tool cover -html=coverage.out

compile: clean goxc

goxc:
	$(shell echo '{\n  "ConfigVersion": "0.9",' > $(GOXC_FILE))
	$(shell echo '  "AppName": "ssh-vault",' >> $(GOXC_FILE))
	$(shell echo '  "ArtifactsDest": "build",' >> $(GOXC_FILE))
	$(shell echo '  "PackageVersion": "${VERSION}",' >> $(GOXC_FILE))
	$(shell echo '  "TaskSettings": {' >> $(GOXC_FILE))
	$(shell echo '    "bintray": {' >> $(GOXC_FILE))
	$(shell echo '      "downloadspage": "bintray.md",' >> $(GOXC_FILE))
	$(shell echo '      "package": "ssh-vault",' >> $(GOXC_FILE))
	$(shell echo '      "repository": "ssh-vault",' >> $(GOXC_FILE))
	$(shell echo '      "subject": "nbari"' >> $(GOXC_FILE))
	$(shell echo '    }\n  },' >> $(GOXC_FILE))
	$(shell echo '  "BuildSettings": {' >> $(GOXC_FILE))
	$(shell echo '    "LdFlags": "-s -w -X main.version=${VERSION}"' >> $(GOXC_FILE))
	$(shell echo '  }\n}' >> $(GOXC_FILE))
	$(shell echo '{\n "ConfigVersion": "0.9",' > $(GOXC_FILE_LOCAL))
	$(shell echo ' "TaskSettings": {' >> $(GOXC_FILE_LOCAL))
	$(shell echo '  "bintray": {\n   "apikey": "$(BINTRAY_APIKEY)"' >> $(GOXC_FILE_LOCAL))
	$(shell echo '  }\n } \n}' >> $(GOXC_FILE_LOCAL))
	${GO_XC}

bintray:
	${GO_XC} bintray

docker:
	docker build -t ssh-vault --build-arg VERSION=${VERSION} .

docker-no-cache:
	docker build --no-cache -t ssh-vault --build-arg VERSION=${VERSION} .

linux:
	docker run --entrypoint "/bin/bash" -it --privileged ssh-vault
