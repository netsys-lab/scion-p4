# Evaluation: Loading packet generator, AES in P4 and the SCION border router with EPIC support into a single Tofino 2

## Build

Each of the repositories has own makefiles to build the P4 code. Please follow the advisements inside these repos for further information.

## Usage

*In case you only have a single cable attached to the Tofino 2, you can use this one to receive AND send frames for testing. Just make sure to comment out the ingress verification table check and set the corresponding variable statically to true. Adapt the switch_config.json files to only include the destination SCION interface and remove the ingress verification table programming from the controller/load_config.py script.*

Run the Tofino model in case you are not on the hardware:
```
$SDE/./run_tofino_model.sh --arch tofino2 -p scion -f <ports.json> -c <multipipe_setup.conf> --int-port-loop 0xf
```

Run the Tofino driver:
```
$SDE/./run_switchd.sh -p scion --arch tofino2 -c <multipipe_setup.conf>
```

Use [evaluation_aes_1pipe.conf](evaluation_aes_1pipe.conf) as `multipipe_setup.conf>` to run the SCION border router and the 1-pipe AES implemenation or the [evaluation_aes_2pipe.conf](evaluation_aes_2pipe.conf) to use the 2-pipe AES implemenation instead.
Use the unified control plane script to initialize all data plane tables and run BFD from the root of this repository (```$P4-SCION-BR```):

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python sudo -E python3 controller/controller.py [--grpc_address <tofino_grpc_address>] -k <scion_key.key> -c <switch_config.json> -i <tofino_interface> [-e <packet_gen_config.yaml> <pipe_pktgen>] [-p <pipe_br> <pipe_aes1> <pipe_aes2>] [-t] [-r <num_repetitions] [-h]
```

where `scion_key.key` is the master0.key SCION key file and `tofino_interface` is the name of the interface to which the Tofino forwards the BFD packets. The `<packet_gen_config.yaml` files we used are stored inside the measurement directories (inisde the measurements folder in the root directory).

The file [switch_config_1seg.json](switch_config_1seg.json) inlcudes the table initialization values for the Tofino that represent the network setup for which 1 segment has to be validated.

The file [switch_config_2seg.json](switch_config_2seg.json) inlcudes the table initialization values for the Tofino that represent the network setup for which 2 segments have to be validated.

The file [evaluation_aes_1pipe.conf](evaluation_aes_1pipe.conf) contains the multipipe-dataplane configuration for pktgen, SCION BR and 1-pipe AES.

The file [evaluation_aes_2pipe.conf](evaluation_aes_2pipe.conf) contains the multipipe-dataplane configuration for pktgen, SCION BR and 2-pipe AES.
