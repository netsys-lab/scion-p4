# Control Plane for SCION EPIC P4 Border Roter

Control plane of the SCION EPIC P4 border router. 

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

