SRC := p4src
INCLUDE := ${SRC}/include/aes.p4 ${SRC}/include/parser.p4
P4FLAGS := "-g --verbose 2"

include ../Makefile.inc

.PHONY: all
all: cmac_pipe0 cmac_pipe1 cmac_test

.PHONY: clean
clean:
	rm -rf build

.PHONY: cmac_pipe0
cmac_pipe0: ${SRC}/cmac_pipe0.p4 build/cmac_pipe0/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/cmac_pipe0.p4: ${INCLUDE}
	@touch $@

.PHONY: cmac_pipe1
cmac_pipe1: ${SRC}/cmac_pipe1.p4 build/cmac_pipe1/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/cmac_pipe1.p4: ${INCLUDE}
	@touch $@

.PHONY: cmac_test
cmac_test: ${SRC}/cmac_test.p4 build/cmac_test/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/cmac_test.p4: ${INCLUDE}
	@touch $@
