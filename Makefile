.DEFAULT: all
.PHONY: all

all: harmonystack

kubestack:
	go build harmonystack.go

install:
	cp -f harmonystack /usr/local/bin/

clean:
	rm -f harmonystack
