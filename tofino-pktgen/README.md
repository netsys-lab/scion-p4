SCION Packet Generator for Intel Tofino 2
=========================================

### Prerequisites
- Intel P4 Studio (SDE) 9.13
- [scapy_scion](https://github.com/lschulz/scapy-scion-int/) must be in `PYTHONPATH`
- Required Python 3 modules:
  - numpy
  - matplotlib
  - pyyaml

### Build
```bash
make
```

### Run model
```bash
sudo $SDE_INSTALL/bin/veth_setup.sh
${SDE}/run_tofino_model.sh --arch tofino2 -p pktgen -f ptf-tests/test_ports.json
${SDE}/run_switchd.sh --arch tf2 -p pktgen
```

### PTF tests
```bash
${SDE}/run_p4_tests.sh --arch tf2 -f ptf-tests/test_ports.json -t ptf-tests
```
Test suites (select with `-s <test suite>`):
- default
- rewrite

### Command Line Interface
```bash
controller/pktgen-cli example_config.yaml
```

```
usage: pktgen-cli [-h] [--grpc_addr GRPC_ADDR] [--client_id CLIENT_ID] [--pipe PIPE] [--clear] [--repeat REPEAT] [--hist-bits HIST_BITS]
                  [--hist-shift HIST_SHIFT] [--out FILE] [--lat-out FILE]
                  config

positional arguments:
  config                Path to configuration file

options:
  -h, --help            show this help message and exit
  --grpc_addr GRPC_ADDR
                        Address of the GRPC server (default: localhost:50052)
  --client_id CLIENT_ID
                        Client ID, will try to find an unused ID if not specified (default: range(0, 10))
  --pipe PIPE           Pipe to use for generating packets (default: 0)
  --clear               Clear all tables before doing anything else (default: False)
  --repeat REPEAT       How many times to repeat the measurements (default: 1)
  --hist-bits HIST_BITS
                        2**hist_bits is the number of histogram bins (max 10 bit) (default: 8)
  --hist-shift HIST_SHIFT
                        Defines the size of the bins in powers of two (default: 6)
  --out FILE            Save report in JSON format to FILE (default: None)
  --lat-out FILE        Save captured packet latencies as Numpy binary file to FILE (default: None)
```

An example for the configuration file is available in [example_config.yaml](./example_config.yaml).

Contributors
------------
- Lars-Christian Schulz, NetSys Lab OvGU Magdeburg
- Robin Wehner, NetSys Lab OvGU Magdeburg
