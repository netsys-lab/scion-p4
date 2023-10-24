Dockerized SCION Topologies
===========================

## The SCION Topology
This directory contains definitions for a SCION star topology with one core AS and six non-core ASes (script: `demo`)

To run the SCION topology use:
```bash
$ ./demo build # Build Docker container
$ ./demo run   # Create SCION configuration and run the topology
$ ./demo stop  # Stop the containers
```
The script assumes scion and the scion-apps repositories to be located directly inside the home directory. If this is not the case, the `SCION_ROOT`and the `SCION_APPS` variables at the top of the script have to be updated.

## The Tofino Setup
The script does only run the SCION infrastructure, the Tofino and its controller have to be started seperately by the following commands:
```bash
$ cd {tofino-scion-br}
$ make # Build Tofino code

$ cd $SDE
$ sudo ./install/bin/veth_setup.sh
$ ./run_tofino_model.sh --arch tofino2 -p scion -f $CONFIG/ports2.json [-q]
$ ./run_switchd.sh --arch tofino2 -p scion [-c $P4SRC/with_cmac_pipe.conf]
```

## The Tofino's Controller
The controller is entirely handled by a single script:
```bash
$ cd {p4-scion-br}
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python sudo -E python3 controller/controller.py [--grpc_address <tofino_grpc_address>] -k <$SCION/gen/$AS_of_the_BR/keys/master0.key> -c <$CONFIG/switch_config.json> -i <tofino_interface> [-p <pipe_br> <pipe_aes1> <pipe_aes2>]
```
where `$SCION` is the location where SCION was cloned and installed. In case the [setup](/VM/setup.sh) script was used, this is directly in your home (`$SCION = ~/scion`). Furthermore, it might be possible that the script is unable to connect to the Tofino - there seems to be an issue where the script is unable to determine the correct gRPC address - then add `--grpc_address <grpc-address-output-by-switchd>` to the command above. Include the `-p` flag if you want to use the p4 AES\_CMAC implementation.

# Troubleshooting

## Get Debug Messages

In case you are not sure whether the scripts are working correctly, you can call them with the `-d` flag which enables debugging output. 
- The BFD Script shows whenever a BFD frame is received and if a corresponding BFD session is configured inside the bfd_config2.json file. It further outputs session state updates.

## The BFD Handling Script does not Receive any Messages

Generally, it should be possible to receive BFD frames on `veth4` and `veth5` of the Tofino 2 setup. However, often only one of them works, when testing this it currently was `veth5`. If it does not work for you, try the other one.

If this does not fix the problem, you can 
1. enter an AS that is not connected to the Tofino (e.g. AS6) and `scion ping` another AS which does not involve the Tofino (e.g. AS1 or AS7). 
 - If it does not work, it is likely that there is a problem with the SCION installation. 
 - If it does work, continue with 2.
2. monitor the `br2tof` interface on which the Tofino connects to the infrastructure (e.g. using Wireshark) and verify that you see (BFD) frames and beacon packets (the only packets that use UDP over SCION if there is no communication possible) sent by the existing SCION infrastructure configuration. 
 - If this is not the case there is an issue with the SCION topology defined in the [demo](demo) script (Try stopping it and running it again, if the last session was stopped successfully using the script it might happen that `run` does not set up everything correctly).
 - If you can see them, the problem might be somewhere in the call of the BFD script. Check, that the directory you provided for the key is the SCION installation the [demo](demo) script uses (if you did not change anything it is `~/scion`).

# When Changing the Setup

The setup is configured inside **the [demo script](demo), the [swicth_config.json](config/switch_config.json) and the [port.json](config/ports.json) files**. If you change one, please change the other ones accordingly to allow the setup to run corretly!
