FROM golang:1.12.7 as builder
ENV GO111MODULE=on

# Prepare for custom caddy build
RUN mkdir /stsclient
WORKDIR /stsclient
RUN go mod init stsclient
RUN go get gotest.tools/assert

RUN echo "replace github.com/russellhaering/goxmldsig => github.com/evtr/goxmldsig latest" >> go.mod

RUN go get github.com/russellhaering/goxmldsig
#RUN go get github.com/russellhaering/gosaml2

# Kitcaddy module source
COPY . /stsclient/
#RUN env
#RUN mv chilkat /go/chilkat
#RUN mv /stsclient/linux-x64-gcc /chilkatc
RUN go test stsclient
RUN CGO_ENABLED=0 GOOS=linux  go build -L/chilkatc/linux-x64-gcc -lchilkatext-9.5.0 -lresolv -lpthread -lstdc++  -a -installsuffix cgo -o /go/bin/securityprotocol .
