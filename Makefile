.DEFAULT: all
.PHONY: all

all: harmonystack

harmonystack:
	go build harmonystack.go

install:
	cp -f harmonystack /usr/local/bin/

clean:
	rm -f harmonystack
