AES-CMAC Using 2 Pipelines
==========================

### Build
```bash
make
```

### Run model
```bash
sudo $SDE_INSTALL/bin/veth_setup.sh

${SDE}/run_tofino_model.sh --arch tofino2 -p cmac_pipe0 --int-port-loop 0x3 \
    -f ptf-tests/test_ports.json -c ptf-tests/test.conf
${SDE}/run_switchd.sh --arch tf2 -c ptf-tests/test.conf
```

### PTF tests
```bash
${SDE}/run_p4_tests.sh --arch tf2 -f ptf-tests/test_ports.json -t ptf-tests
```

Header
------
The program accept Ethernet packets with protocol type `0x9999` followed by the
following header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|A|B|               Reserved              |   Egress Port   |Rsv|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               | \
|                                                               | |
|                     Message 0 (16 bytes)                      | |
|                                                               | | If A is set
|                                                               | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
|                   MAC 0 truncated to 6 bytes                  | /
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
|                               |                               | \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               | |
|                                                               | |
|                     Message 1 (16 bytes)                      | |
|                                                               | | If B is set
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
|                               |                               | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               | |
|                   MAC 1 truncated to 6 bytes                  | /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Payload                            |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- If flag **A** is set, the AES-CMAC of **Message 0** is compared to the
  truncated **MAC 0**.
- If flag **B** is set, the AES-CMAC of **Message 1** is compared to the
  truncated **MAC 1**.
- If any computed MAC does not compare equal to the MAC in the packet, the
  packet is dropped. Otherwise, the payload is forwarded to **Egress Port**
  without the Ethernet and MAC headers just described.
