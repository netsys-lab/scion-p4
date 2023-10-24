AES-ECB Using 1 Pipeline
========================

### Build
```bash
make
```

### Run model
```bash
sudo $SDE_INSTALL/bin/veth_setup.sh

${SDE}/run_tofino_model.sh --arch tofino2 -p aes_1pipe --int-port-loop 0x1 \
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
|A|B|0|Reserved |   Reserved    |           User Data           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               | \
|                       Block 0 (16 bytes)                      | | If A is set
|                                                               | /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               | \
|                       Block 1 (16 bytes)                      | | If B is set
|                                                               | /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Key (16 bytes)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Block 0** is encrypted with **Key** if flag **A** is set.
- **Block 1** is encrypted with **Key** if flag **B** is set.
- **User Data** is arbitrary data that is carried through the pipeline unchanged.
