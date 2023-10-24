THIS REPOSITORY IS BASED ON THE [SIDN-LABS P4 IMPLEMENTATION OF SCION](https://github.com/SIDN/p4-scion)!

# SCION P4 Border Router Supporting External AES Accelerators

**This is a prototype implementation and is currently not intended for use in production.**

This is a P4 implementation of a SCION border router with support for an external accelerator targeting an Intel Tofino 2 switch.

## Folder struture

- [controller](controller/) includes the control plane Python scripts
- [evaluation](evaluation/) includes submodules for AES in P4 and the Tofino packet generator as well as a configuration to load everything into different pipes of the Tofino
- [measurements](measurements/) contains the measurement results
- [p4src](p4src/) is the folder for the P4 source code
- [test_infrastructure](test_infrastructure/) contains a script to set up a dockerized SCION testbed and the according files to configure the Tofino model for this testbed
- [test_traffic](test_traffic/) includes different pcap files from both sides of a SCION reference border router that can be replayed for functionality testing
- [VM](VM/) contains the scripts to set up a new VM or to install all prerequesites needed to run the dockerized SCION testbed

## Prerequisites

Please make sure Python3 und pip3 are installed.

This repository includes a simple Docker encapsulated SCION testbed. To run this, SCION, Docker and Bazel have to be installed. This can also be done using the [Docker installation script](VM/install_docker.sh) and the [Setup script](VM/setup.sh) inside the [VM](VM/) folder. There is also a [Vagrant file](VM/Vagrantfile) existent in case a whole new VM should be set up.

Furthermore a current BF SDE version is needed (tested with 9.13.0).

## Build

**The code currently does not compile for Tofino 1.**

Compile the P4 code for Tofino 2 (Requires the p4_build script from the SDE):

```
make
```

Make sure that the `PORT_CPU` constant in `scion.p4` matches with the port that will be used later to receive packets for processing the BFD frames in the control plane.

By default support for both IPv4 and IPv6 is enabled. This can be disabled by using the flag `-DDISABLE_IPV4` or `-DDISABLE_IPV6` respectively. Note that the flags cannot be used at the same time.

## Usage

**For the control plane applications make sure that the `bfrt_grpc` folder is in your `PYTHONPATH`.**

### Deployment without the AES-CMAC P4 implementation

Run the P4 code on the Tofino hardware as follows:
```
$SDE/run_switchd.sh --arch tofino2 -p scion
```

To initialize the data plane tables run:

```
python3 controller/load_config.py <switch_config.json> 
```

To start the BFD processing which is necessary to communicate with other SCION border routers:

```
sudo -E python3 controller/bfd_handling.py -b <bfd_config.json> -k <scion_key.key> -i <tofino_interface>
```
where `scion_key.key` is the master0.key SCION key file and `tofino_interface` is the name of the interface to which the Tofino forwards the BFD packets.

Instead of the previous two commands, you can also use the unified controller:
```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python sudo -E python3 controller/controller.py [--grpc_address <tofino_grpc_address>] -k <scion_key.key> -c <switch_config.json> -i <tofino_interface>
```

### Deployment with the AES-CMAC P4 implementation

Run the P4 code on the Tofino hardware as follows:
```
$SDE/run_switchd.sh --arch tofino2 -p scion -c <pipeline_config.conf>
```

Example Config files are [p4src/with_cmac_1pipe.conf](p4src/with_cmac_1pipe.conf) which starts the data plane of the SCION border router and the 1-pipe implementation of AES\_CMAC or [p4src/with_cmac_2pipe.conf](p4src/with_cmac_2pipe.conf) to use the 2-pipe implementation of AES\_CMAC instead.

Please use the unified controller script which handles all control plane tasks:
```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python sudo -E python3 controller/controller.py [--grpc_address <tofino_grpc_address>] -k <scion_key.key> -c <switch_config.json> -i <tofino_interface> -p <pipe_br> <pipe_aes1> <pipe_aes2>
```

In case you are using the 1-pipe implementation of AES\_CMAC, enter the pipe in which the program is loaded for `<pipe_aes1>` as well as for `<pipe_aes2>`, the controller detects that as the 1-pipe implementation and configures the data plane in the corresponding way.

**In [test_infrastructure/README.md](test_infrastructure/README.md), an explanation can be found to run the P4 implementation using the Tofino model and a SCION example setup.**

**A description on how to reproduce the measurements can be found inside [evaluation/README.md](evaluation/README.md).**

## Limitations

Currently the following features are not yet provided:
- Peering connections
- Mixing of IPv4 and IPv6
- SCMP
- Support to process EPIC-HP (In ongoing work) and COLIBRI paths

## Authors

- Robin Wehner, NetSys Lab OvGU Magdeburg
- Lars-Christian Schulz, NetSys Lab OvGU Magdeburg.

The [P4 implementation of a SCION border router](https://github.com/SIDN/p4-scion) we based our work on and of which some files are still present inside this repository was developed by:
- Joeri de Ruiter, SIDN Labs
- Caspar Schutijser, SIDN Labs
