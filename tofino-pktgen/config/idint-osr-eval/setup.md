OSR ID-INT Experiment
=====================

Configuration
-------------

Epyc 2 connects to Tofino on port 18 and 19.

### Preparations: Tofino
- switchd
```bash
${SDE}/run_switchd.sh -p pktgen --arch tofino2
```

- Port Manager
port-add 18/0 100G RS
port-add 19/0 100G RS
an-set 18/0 enable
an-set 19/0 enable
port-enb 18/0
port-enb 19/0

### Preparations: Server (Epyc2)
sudo ip addr add 10.1.4.1/24 dev enp65s0np0
sudo ip addr add 10.1.5.1/24 dev enp129s0np0
sudo ip link set enp65s0np0 up
sudo ip link set enp129s0np0 up
sudo arp -s 10.1.4.2 d6:a9:96:c4:0f:9e
sudo arp -s 10.1.5.2 d6:a9:96:c4:0f:9f

### Run border router
```bash
~/scion/bin/router --config osr-config/br.toml
```

### Run traffic generator
```bash
python3 config/idint-osr-eval/gen_packets.py
export PYTHONPATH=$(pwd):~/lars/scapy-scion-int:$PYTHONPATH
controller/pktgen-cli config/idint-osr-eval/packets/pktgen.yaml --pipe 3
```

Evaluation
----------
1. Inst[0] = IntInstZero8 (a) Encrypt = false (b) Encrypt = true
2. Inst[0:1] = IntInstZero8 (a) Encrypt = false (b) Encrypt = true
3. Inst[0:2] = IntInstZero8 (a) Encrypt = false (b) Encrypt = true
4. Inst[0:3] = IntInstZero8 (a) Encrypt = false (b) Encrypt = true
5. Inst[0:3] = IntInstZero8, ReqNodeId = true, ReqNodeCount = true, ReqIngressIf = true, ReqEgressIf = true
   (a) Encrypt = false (b) Encrypt = true
