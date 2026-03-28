PREFIX ?= /usr/local
BIN_NAME ?= shep32-cpp

.PHONY: build install uninstall clean

build:
	./build.sh

install:
	./install.sh --prefix "$(PREFIX)" --bin-name "$(BIN_NAME)"

uninstall:
	./uninstall.sh --prefix "$(PREFIX)" --bin-name "$(BIN_NAME)"

clean:
	rm -f ./bin/shep32-cpp
