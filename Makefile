.PHONY: test cover attacker broker demo tidy

test:
	go test ./... -count=1

cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html

attacker:
	go run ./cmd/attacker

broker:
	go run ./cmd/broker

demo:
	go run ./cmd/demo-agent

tidy:
	go mod tidy
