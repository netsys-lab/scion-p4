# SPDX-License-Identifier: BSD-3-Clause AND AGPL-3.0-or-later

# Copyright (c) 2021, SIDN Labs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import ipaddress
import json
import logging

from tofino import *

logger = logging.getLogger('scion_load_config')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Create Interface ti communicate with Tofino
class Interface:
    def __init__(self, grpc_addr = 'localhost:50052', dev=0, client_id=0):
        self.dev_tgt = gc.Target(dev, pipe_id=0xFFFF)
        self.interface = gc.ClientInterface(grpc_addr,
                                            client_id=client_id,
                                            device_id=dev)
        self.interface.bind_pipeline_config(p4_name)

    def get_if(self):
        return self.interface

    def get_dev_tgt(self):
        return self.dev_tgt

# Create P4 port number from pipe and port
def _make_port(pipe: int, port: int) -> int:
    """Make port number from pipe ID and port within the pipe."""
    return (pipe << 7) | port

# Load config to Tofino
def load_configuration(config_file, interface, dev_tgt, p4_name, key, subkey, br_pipes=[0,1,2,3], aes_pipes=[]):
    configJSON = open(config_file)
    config = json.load(configJSON)

    p4_name = p4_name

    bfrt_info = interface.bfrt_info_get(p4_name)

    # Tables will be emptied and refilled with information from config file

    #TODO Be able to handle odd-length AS strings
    tbl_check_local = TblCheckLocal(dev_tgt, bfrt_info)
    tbl_check_local.clear()

    logger.info("Adding local ISD-AS info")
    tbl_check_local.entry_add_NoAction(config['localISD'],
                                       int(config['localAS'], 16))
    
    # Init tables for ingress verification and completion (in case of one-hop)
    tbl_ingress_verification = TblIngressVerification(dev_tgt, bfrt_info)
    tbl_ingress_verification.clear()
    tbl_ingress_interface = TblIngressInterface(dev_tgt, bfrt_info)
    tbl_ingress_interface.clear()

    logger.info("Adding interfaces")
    for e in config['interfaces']:
        tbl_ingress_verification.entry_add_NoAction(e['interface'],
                                                    e['portId'])
    for e in config['externalInterfaces']:
        tbl_ingress_interface.entry_add_set_ingress_interface(
            e['interface'], e['portId'])
    
    # Init tables for key insertion into bridge header
    tbl_bridge_key = TblBridgeKey(dev_tgt, bfrt_info)
    tbl_bridge_subkey = TblBridgeSubkey(dev_tgt, bfrt_info)
    tbl_bridge_key.clear()
    tbl_bridge_subkey.clear()

    logger.info("Adding keys")
    tbl_bridge_key.entry_add_insert_bridge_key(0, key)
    tbl_bridge_subkey.entry_add_bridge_subkey_hop1(0, subkey)
    tbl_bridge_subkey.entry_add_bridge_subkey_hop2(1, subkey)

    # Init LAG tables for external accelerator selection
    tbl_accelerator_lag = TblAcceleratorLag(dev_tgt, bfrt_info)
    tbl_accelerator_lag_sel = TblAcceleratorLagSel(dev_tgt, bfrt_info)
    tbl_select_accelerator = TblSelectAccelerator(dev_tgt, bfrt_info)
    tbl_select_accelerator.clear()
    tbl_accelerator_lag_sel.clear()
    tbl_accelerator_lag.clear()
    actionMembers = {}
    i = 0
    if aes_pipes != []:
        for br_pipe in br_pipes:
            for port in range(8, 72):
                if _make_port(br_pipe, port) not in actionMembers.keys():
                    actionMembers[_make_port(br_pipe, port)] = []
                actionMembers[_make_port(br_pipe, port)].append([i, _make_port(aes_pipes[i % len(aes_pipes)], port), 
                    bytearray(b'\x00\x00\x00\x00\x00\x00'), bytearray(b'\x00\x00\x00\x00\x00\x00'), _make_port(br_pipe, port)])
                i = i + 1
    else:
        actionMembers[0] = []
        for e in config['externalAccelerators']:
            actionMembers[0].append([i, e['portId'], mac_to_bytes(e['dstMAC']), mac_to_bytes(e['srcMAC'])])
            i = i + 1
    for value in actionMembers.values():
        for member in value:
            tbl_accelerator_lag.entry_add_create_bridge_hdr(member[0], member[1], member[2], member[3])
    for key in actionMembers.keys():
        tbl_accelerator_lag_sel.entry_add(key, actionMembers[key])
        if key == 0:
            tbl_select_accelerator.entry_add(key, 0x0000)
        else:
            tbl_select_accelerator.entry_add(key, 0x1ff)

    # Init local forwarding tables
    tbl_deliver_local = TblDeliverLocal(dev_tgt, bfrt_info)
    tbl_deliver_local.clear()
    tbl_deliver_local_empty = TblDeliverLocalEmpty(dev_tgt, bfrt_info)
    tbl_deliver_local_empty.clear()

    logger.info("Adding border routers")
    for e in config['localBorderRouters']:
        try:
            addr = ipaddress.ip_address(e['host'])
            if isinstance(addr, ipaddress.IPv4Address):
                tbl_deliver_local_empty.entry_add_deliver_local_ipv4(
                    e['dt'], e['dl'], ipv4_to_bytes(e['host']),
                    e['egressPortId'], mac_to_bytes(e['dstMAC']), e['dstPort'])
            elif isinstance(addr, ipaddress.IPv6Address):
                tbl_deliver_local_empty.entry_add_deliver_local_ipv6(
                    e['dt'], e['dl'], ipv6_to_bytes(e['host']),
                    e['egressPortId'], mac_to_bytes(e['dstMAC']), e['dstPort'])
        except ValueError:
            logger.info("Invalid address: %s / %s", e['host'])


    logger.info("Adding local destinations")
    for e in config['localDestinations']:
        try:
            addr = ipaddress.ip_address(e['host'])
            mask = ipaddress.ip_address(e['netmask'])
            if isinstance(addr, ipaddress.IPv4Address):
                tbl_deliver_local.entry_add_deliver_local_ipv4(
                    e['dt'], e['dl'], ipv4_to_bytes(e['host']), ipv4_to_bytes(e['netmask']),
                    e['egressPortId'], mac_to_bytes(e['dstMAC']), e['dstPort'])
            elif isinstance(addr, ipaddress.IPv6Address):
                tbl_deliver_local.entry_add_deliver_local_ipv6(
                    e['dt'], e['dl'], ipv6_to_bytes(e['host']), ipv6_to_bytes(e['netmask']),
                    e['egressPortId'], mac_to_bytes(e['dstMAC']), e['dstPort'])
        except ValueError:
            logger.info("Invalid address or netmask: %s / %s", e['host'], e['netmask'])


    logger.info("Adding local services")
    for e in config['localDestinationsService']:
        try:
            addr = ipaddress.ip_address(e['host'])
            if isinstance(addr, ipaddress.IPv4Address):
                tbl_deliver_local.entry_add_deliver_local_service_ipv4(
                    e['dt'], e['dl'], e['host'], e['egressPortId'],
                    ipv4_to_bytes(e['dstIP']), mac_to_bytes(e['dstMAC']), e['dstPort'])
            elif isinstance(addr, ipaddress.IPv6Address):
                tbl_deliver_local.entry_add_deliver_local_service_ipv6(
                    e['dt'], e['dl'], e['host'], e['egressPortId'],
                    ipv6_to_bytes(e['dstIP']), mac_to_bytes(e['dstMAC']), e['dstPort'])
        except ValueError:
            logger.info("Invalid address: %s", e['host'])

    # Init remote forwarding table
    tbl_forward = TblForward(dev_tgt, bfrt_info)
    tbl_forward.clear()

    logger.info("Adding fowarding info")
    for e in config['forwardLocal']:
        try:
            addr = ipaddress.ip_address(e['dstIP'])
            if isinstance(addr, ipaddress.IPv4Address):
                tbl_forward.entry_add_forward_local_ipv4(e['egressInterface'], e['egressPortId'],
                                              ipv4_to_bytes(e['dstIP']),
                                              mac_to_bytes(e['dstMAC']), e['dstPort'])
            elif isinstance(addr, ipaddress.IPv6Address):
                tbl_forward.entry_add_forward_local_ipv6(e['egressInterface'], e['egressPortId'],
                                              ipv6_to_bytes(e['dstIP']),
                                              mac_to_bytes(e['dstMAC']), e['dstPort'])
        except ValueError:
            logger.info("Invalid address: %s", e['dstIP'])

    for e in config['forwardRemote']:
        try:
            addr = ipaddress.ip_address(e['dstIP'])
            if isinstance(addr, ipaddress.IPv4Address):
                tbl_forward.entry_add_forward_remote_ipv4(e['egressInterface'], e['egressPortId'],
                                              ipv4_to_bytes(e['dstIP']),
                                              mac_to_bytes(e['dstMAC']), e['dstPort'])
            elif isinstance(addr, ipaddress.IPv6Address):
                tbl_forward.entry_add_forward_remote_ipv6(e['egressInterface'], e['egressPortId'],
                                              ipv6_to_bytes(e['dstIP']),
                                              mac_to_bytes(e['dstMAC']), e['dstPort'])
        except ValueError:
            logger.info("Invalid address: %s", e['dstIP'])

    # Init table with local address information
    tbl_set_local_source = TblSetLocalSource(dev_tgt, bfrt_info)
    tbl_set_local_source.clear()

    logger.info("Adding source information for ports")
    for e in config['localSource']:
        try:
            addr = ipaddress.ip_address(e['srcIP'])
            if isinstance(addr, ipaddress.IPv4Address):
                tbl_set_local_source.entry_add_ipv4(e['egressPortId'],
                                           ipv4_to_bytes(e['srcIP']),
                                           mac_to_bytes(e['srcMAC']), e['srcPort'])
            elif isinstance(addr, ipaddress.IPv6Address):
                tbl_set_local_source.entry_add_ipv6(e['egressPortId'],
                                           ipv6_to_bytes(e['srcIP']),
                                           mac_to_bytes(e['srcMAC']), e['srcPort'])
        except ValueError:
            logger.info("Invalid address: %s", e['srcIP'])

