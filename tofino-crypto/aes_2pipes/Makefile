SRC := p4src
INCLUDE := ${SRC}/include/aes.p4 ${SRC}/include/parser.p4
P4FLAGS := "-g --verbose 2"

include ../Makefile.inc

.PHONY: all
all: aes_pipe0 aes_pipe1 aes_test

.PHONY: clean
clean:
	rm -rf build

.PHONY: aes_pipe0
aes_pipe0: ${SRC}/aes_pipe0.p4 build/aes_pipe0/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_pipe0.p4: ${INCLUDE}
	@touch $@

.PHONY: aes_pipe1
aes_pipe1: ${SRC}/aes_pipe1.p4 build/aes_pipe1/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_pipe1.p4: ${INCLUDE}
	@touch $@

.PHONY: aes_test
aes_test: ${SRC}/aes_test.p4 build/aes_test/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_test.p4: ${INCLUDE}
	@touch $@
