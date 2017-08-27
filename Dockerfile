FROM golang:1.9

WORKDIR /go/src/github.com/ssh-vault/ssh-vault
copy . .

ENV GOPATH /go
ENV GOROOT /usr/local/go
ENV PATH /usr/local/go/bin:/go/bin:/usr/local/bin:$PATH

RUN make test

CMD /bin/bash
