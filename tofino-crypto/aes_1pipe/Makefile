SRC := p4src
INCLUDE := ${SRC}/include/aes.p4 ${SRC}/include/parser.p4
P4FLAGS := "-g --verbose 2"

include ../Makefile.inc

.PHONY: all
all: aes_1pipe aes_1pipe_test

.PHONY: clean
clean:
	rm -rf build

.PHONY: aes_1pipe
aes_1pipe: ${SRC}/aes_1pipe.p4 build/aes_1pipe/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_1pipe.p4: ${INCLUDE}
	@touch $@

.PHONY: aes_1pipe_test
aes_1pipe_test: ${SRC}/aes_1pipe_test.p4 build/aes_1pipe_test/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_1pipe_test.p4: ${INCLUDE}
	@touch $@
