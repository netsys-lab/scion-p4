ifndef SDE
$(error SDE is not defined)
endif

ifndef SDE_INSTALL
$(error SDE_INSTALL is not defined)
endif

SRC := p4src
P4FLAGS := "-g --verbose 2"

.PHONY: all
all: pktgen

.PHONY: clean
clean:
	rm -rf build

.PHONY: pktgen
pktgen: ${SRC}/pktgen.p4 build/pktgen/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

build/%/Makefile: ${SRC}/%.p4
	cmake ${SDE}/p4studio -B build/$* \
		-DCMAKE_MODULE_PATH=${SDE}/cmake \
		-DCMAKE_INSTALL_PREFIX="${SDE_INSTALL}" \
		-DP4_PATH="$(realpath $<)" \
		-DP4_NAME="$(basename $(nodir $<))" \
		-DP4_LANG=p4-16 \
		-DTOFINO2=ON \
		-DP4FLAGS=${P4FLAGS}
