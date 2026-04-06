FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/gvisor-docker-patch ./main.go

FROM alpine:3.21

RUN apk add --no-cache iproute2 jq procps

WORKDIR /app
COPY --from=builder /out/gvisor-docker-patch /app/gvisor-docker-patch
COPY setup_netns.sh /app/setup_netns.sh

ENTRYPOINT ["/app/gvisor-docker-patch"]
