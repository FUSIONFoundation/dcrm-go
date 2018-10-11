.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/fusion/go-fusion/cmd/swarm
	go build -o bin/geth     github.com/fusion/go-fusion/cmd/geth
	go build -o bin/bootnode github.com/fusion/go-fusion/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/fusion/go-fusion/swarm/...
