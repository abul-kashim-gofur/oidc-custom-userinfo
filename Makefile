build:
	rm -r .bin || true 
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-tags lambda.norpc \
		-o ./.bin/bootstrap \
		-ldflags "-s -w" \
		-trimpath \
		./cmd/userinfo/main.go
	
	zip -j -9 ./.bin/userinfo.zip "./.bin/bootstrap"
	rm ./.bin/bootstrap
.PHONY: build

test:
	go test --race ./...
.PHONY: test

lint:
	golangci-lint run ./...
.PHONY: lint