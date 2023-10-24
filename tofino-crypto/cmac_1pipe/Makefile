SRC := p4src
INCLUDE := ${SRC}/include/aes.p4 ${SRC}/include/parser.p4
P4FLAGS := "-g --verbose 2"

include ../Makefile.inc

.PHONY: all
all: cmac_1pipe cmac_1pipe_test

.PHONY: clean
clean:
	rm -rf build

.PHONY: cmac_1pipe
cmac_1pipe: ${SRC}/cmac_1pipe.p4 build/cmac_1pipe/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/cmac_1pipe.p4: ${INCLUDE}
	@touch $@

.PHONY: cmac_1pipe_test
cmac_1pipe_test: ${SRC}/cmac_1pipe_test.p4 build/cmac_1pipe_test/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/cmac_1pipe_test.p4: ${INCLUDE}
	@touch $@
