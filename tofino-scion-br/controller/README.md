# Control Plane for SCION P4 Border Roter

Control plane of the SCION P4 border router. 

## Installation

```
apt install libprotobuf-dev
pip3 install -r requirements.txt
```

### bfrt_grpc

In order to work with the control plane scripts, `bfrt_grpc`has to be in you `PYTHONPATH`. The simplest way to achieve this is to run the `set_sde.bash` script from the SDE.

## Applications

Scripts to run the Tofino on hardware:
- `controller.py`: Unified controller that includes functionalities of both:
  - `load_config.py`: Initialize the P4 border router with a given SCION configuration
  - `bfd_handling.py`: Run the BFD protocol on Tofino.

Additional tools for testing and measurements:
- `test.py`: Program that loads a reference .pcap file from [test_traffic](../test_traffic/) and checks whether the packets received from the Tofino match those in the .pcap file. Can be used with the pcap files in the `test_traffic` folder of the repository root in combination with tcpreplay to send packets to the Tofino.
