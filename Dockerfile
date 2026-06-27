# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./...
RUN CGO_ENABLED=0 go build -o /out/broker ./cmd/broker
RUN CGO_ENABLED=0 go build -o /out/demo-agent ./cmd/demo-agent
RUN CGO_ENABLED=0 go build -o /out/attacker ./cmd/attacker

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl python3
WORKDIR /app
COPY --from=build /out/broker /out/demo-agent /out/attacker /app/
COPY scripts /app/scripts
COPY redteam/scenarios /app/redteam/scenarios
COPY proto /app/proto
EXPOSE 8080
ENV BROKER_ADDR=:8080
ENV DB_PATH=/data/broker.db
ENV SIGNING_KEY_PATH=/data/signing.key
VOLUME ["/data"]
CMD ["/app/broker"]
