BINARY_NAME=controller
GO_ENV=GO111MODULE=on
DOCKER_IMAGE=docker.io/dereulenspiegel/nginx-controller

VERSION 				?= $(shell git describe --tags --always --dirty)
RELEASE_VERSION		?= $(shell git describe --abbrev=0)
LDFLAGS       	?= -X github.com/dereulenspiegel/nginx-controller/pkg/nginx.Version=$(VERSION) -w -s

GO_BUILD=$(GO_ENV) go build -ldflags "$(LDFLAGS)"
GO_TEST=$(GO_ENV) go test -v

.PHONY: clean test docker docker.build docker.push
.DEFAULT_GOAL := build

build: $(BINARY_NAME)

$(BINARY_NAME):
	$(GO_BUILD) -o $(BINARY_NAME) ./cmd/controller

docker: docker.build docker.push

docker.multiarch.push:
	docker buildx build \
		--platform linux/amd64,linux/arm64,linux/arm/v7 \
		--output=type=image,push=true \
		-t $(DOCKER_IMAGE):$(VERSION) .

docker.build: test
	docker build . -t $(DOCKER_IMAGE):$(VERSION)

docker.push:
	docker push $(DOCKER_IMAGE):$(VERSION)

test:
	$(GO_TEST) ./...

clean:
	rm -f controller
