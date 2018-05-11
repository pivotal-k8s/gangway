FROM golang:1.9
WORKDIR /go/src/github.com/heptiolabs/gangway

# RUN go get github.com/golang/dep/cmd/dep
# COPY Gopkg.toml Gopkg.lock ./
# RUN dep ensure -v -vendor-only

COPY vendor vendor

COPY cmd cmd
RUN CGO_ENABLED=0 GOOS=linux go install -ldflags="-w -s" -v github.com/heptiolabs/gangway/...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=0 /go/bin/gangway /bin/gangway
