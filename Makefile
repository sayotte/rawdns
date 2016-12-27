PROJ = github.com/sayotte/rawmdns

all: test vet build

test:
	go test -cover ${PROJ}

vet:
	go get github.com/golang/lint/golint
	#bin/golint
	go vet ${PROJ}

build:
	go build ${PROJ}
