FROM golang:latest as builder
RUN go get -u github.com/golang/dep/cmd/dep
WORKDIR /go/src/github.com/ssh-vault/ssh-vault
copy . .
ARG VERSION=0.0.0
ENV VERSION="${VERSION}"
RUN dep ensure --vendor-only
RUN make test
RUN make build-linux
