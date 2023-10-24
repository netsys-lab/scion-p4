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

import bfrt_grpc.client as gc

from bfrt_grpc.client import mac_to_bytes, ipv4_to_bytes, ipv6_to_bytes, bytes_to_int

import time
import binascii

class Tbl(object):
    def __init__(self, dev_tgt, bfrt_info, tbl_name):
        self.dev_tgt = dev_tgt
        self.bfrt_info = bfrt_info
        self.tbl = bfrt_info.table_get(tbl_name)

    def clear(self):
        self.tbl.entry_del(self.dev_tgt)

    def get_entries(self):
        # We use empty flags as the default value ({"from_hw": True}) results in an exception on the model
        return self.tbl.entry_get(self.dev_tgt, flags={})

    def entry_del(self, key):
        return self.tbl.entry_del(self.dev_tgt, [key])

class TblIngressVerification(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblIngressVerification,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_ingress_verification")

    def make_key(self, hfIngress, ingressPort):
        return self.tbl.make_key([
            gc.KeyTuple('meta.ingress', hfIngress),
            gc.KeyTuple('ig_intr_md.ingress_port', ingressPort),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, hfIngress, ingressPort):
        key = self.make_key(hfIngress, ingressPort)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblIngressInterface(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblIngressInterface,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_ingress_interface")

    def make_key(self, ingressPort):
        return self.tbl.make_key([
            gc.KeyTuple('ig_intr_md.ingress_port', ingressPort),
        ])

    def make_data_set_ingress_interface(self, hfIngress):
        return self.tbl.make_data([
            gc.DataTuple('inIf', hfIngress),
        ], "set_ingress_interface")

    def entry_add_set_ingress_interface(self, hfIngress, ingressPort):
        key = self.make_key(ingressPort)
        data = self.make_data_set_ingress_interface(hfIngress)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblAcceleratorLag(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblAcceleratorLag,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.lag_ecmp")

    def make_key(self, actionMemberId):
        return self.tbl.make_key([
            gc.KeyTuple('$ACTION_MEMBER_ID', actionMemberId),
        ])

    def make_data(self, port, dstMac, srcMac):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dst', dstMac),
            gc.DataTuple('src', srcMac),
        ], "create_bridge_hdr")

    def entry_add_create_bridge_hdr(self, actionMemberId, port, dstMac, srcMac):
        key = self.make_key(actionMemberId)
        data = self.make_data(port, dstMac, srcMac)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblAcceleratorLagSel(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblAcceleratorLagSel,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.lag_ecmp_sel")

    def make_key(self, selGroupID):
        return self.tbl.make_key([
            gc.KeyTuple('$SELECTOR_GROUP_ID', selGroupID),
        ])

    def make_data(self, actionMembers):
        actionMemberIds = []
        actionMemberStates = []
        for member in actionMembers:
            actionMemberIds.append(member[0])
            actionMemberStates.append(True)
        return self.tbl.make_data([
            gc.DataTuple('$MAX_GROUP_SIZE', 64),
            gc.DataTuple(name='$ACTION_MEMBER_ID', int_arr_val=actionMemberIds),
            gc.DataTuple('$ACTION_MEMBER_STATUS', bool_arr_val=actionMemberStates),
        ])

    def entry_add(self, selGroupID, actionMembers):
        key = self.make_key(selGroupID)
        data = self.make_data(actionMembers)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblSelectAccelerator(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblSelectAccelerator,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_select_accelerator")

    def make_key(self, inPort, mask):
        return self.tbl.make_key([
            gc.KeyTuple('ig_intr_md.ingress_port', inPort, mask),
        ])

    def make_data(self, selGroupID):
        return self.tbl.make_data([
            gc.DataTuple('$SELECTOR_GROUP_ID', selGroupID),
        ])

    def entry_add(self, inPort, mask):
        key = self.make_key(inPort, mask)
        data = self.make_data(inPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblCheckLocal(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblCheckLocal, self).__init__(dev_tgt, bfrt_info,
                                            "ScionIngressControl.tbl_check_local")

    def make_key(self, isd, asn):
        return self.tbl.make_key([
            gc.KeyTuple('hdr.scion_addr_common.dstISD', isd),
            gc.KeyTuple('hdr.scion_addr_common.dstAS', asn),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, isd, asn):
        key = self.make_key(isd, asn)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblBfdRemote(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblBfdRemote, self).__init__(dev_tgt, bfrt_info,
                                            "ScionIngressControl.tbl_bfd_remote")

    def make_key(self, egIfId):
        return self.tbl.make_key([
            gc.KeyTuple('meta.egress', egIfId),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, egIfId):
        key = self.make_key(egIfId)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_del(self, egIfId):
        key = self.make_key(egIfId)
        return super(TblBfdRemote, self).entry_del(key)


class TblBfdLocal(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblBfdLocal, self).__init__(dev_tgt, bfrt_info,
                                            "ScionIngressControl.tbl_bfd_local")

    def make_key(self, destLen, destType, destIpv4, destIpv4Mask, destIpv6, destIpv6Mask):
        return self.tbl.make_key([
            gc.KeyTuple('hdr.scion_common.dl', destLen),
            gc.KeyTuple('hdr.scion_common.dt', destType),
            gc.KeyTuple('hdr.scion_addr_dst_host_32.host', destIpv4, destIpv4Mask),
            gc.KeyTuple('hdr.scion_addr_dst_host_128.host', destIpv6, destIpv6Mask),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, dl, dt, dstIpv4, dstIpv6):
        key = self.make_key(dl, dt, dstIpv4, 0xFFFFFFFF, dstIpv6, 0xFFFFFFFF)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_del(self, dl, dt, dstIpv4, dstIpv6):
        key = self.make_key(dl, dt, dstIpv4, 0xFFFFFFFF, dstIpv6, 0xFFFFFFFF)
        return super(TblBfdLocal, self).entry_del(key)


class TblDeliverLocalEmpty(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblDeliverLocalEmpty, self).__init__(dev_tgt, bfrt_info,
                                              "ScionIngressControl.tbl_deliver_local_empty")
    def make_key(self, destType, destLen, destIpv4, destIpv4Mask, destIpv6, destIpv6Mask):
        return self.tbl.make_key([
            gc.KeyTuple('hdr.scion_common.dl', destLen),
            gc.KeyTuple('hdr.scion_common.dt', destType),
            gc.KeyTuple('hdr.scion_addr_dst_host_32.host', destIpv4, destIpv4Mask),
            gc.KeyTuple('hdr.scion_addr_dst_host_128.host', destIpv6, destIpv6Mask),
        ])

    def make_data_deliver_local_ipv6(self, port, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_ipv6")

    def entry_add_deliver_local_ipv6(self, destType, destLen, dest,
                                     port, dstMAC, dstPort):
        key = self.make_key(destType, destLen, 0, 0, dest, 0xFFFFFFFF)
        data = self.make_data_deliver_local_ipv6(port, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


    def make_data_deliver_local_ipv4(self, port, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_ipv4")

    def entry_add_deliver_local_ipv4(self, destType, destLen, dest,
                                     port, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, 0xFFFFFFFF, 0, 0)
        data = self.make_data_deliver_local_ipv4(port, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

class TblDeliverLocal(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblDeliverLocal, self).__init__(dev_tgt, bfrt_info,
                                              "ScionIngressControl.tbl_deliver_local")
    def make_key(self, destType, destLen, destIpv4, destIpv4Mask, destIpv6, destIpv6Mask):
        return self.tbl.make_key([
            gc.KeyTuple('hdr.scion_common.dl', destLen),
            gc.KeyTuple('hdr.scion_common.dt', destType),
            gc.KeyTuple('hdr.scion_addr_dst_host_32.host', destIpv4, destIpv4Mask),
            gc.KeyTuple('hdr.scion_addr_dst_host_128.host', destIpv6, destIpv6Mask),
        ])

    def make_data_deliver_local_ipv6(self, port, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_ipv6")

    def entry_add_deliver_local_ipv6(self, destType, destLen, dest, destMask,
                                     port, dstMAC, dstPort):
        key = self.make_key(destType, destLen, 0, 0, dest, destMask)
        data = self.make_data_deliver_local_ipv6(port, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


    def make_data_deliver_local_ipv4(self, port, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_ipv4")

    def entry_add_deliver_local_ipv4(self, destType, destLen, dest, destMask,
                                     port, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, destMask, 0, 0)
        data = self.make_data_deliver_local_ipv4(port, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_deliver_local_service_ipv4(self, port, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_service_ipv4")

    def entry_add_deliver_local_service_ipv4(self, destType, destLen, dest, port,
                                        dstIP, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, 0xFFFFFFFF, 0, 0)
        data = self.make_data_deliver_local_service_ipv4(port, dstIP, dstMAC,
                                                    dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_deliver_local_service_ipv6(self, port, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_service_ipv6")

    def entry_add_deliver_local_service_ipv6(self, destType, destLen, dest, port,
                                        dstIP, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, 0xFFFFFFFF, 0, 0)
        data = self.make_data_deliver_local_service_ipv6(port, dstIP, dstMAC,
                                                    dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblForward(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblForward, self).__init__(dev_tgt, bfrt_info,
                                         "ScionIngressControl.tbl_forward")

    def make_key(self, hfEgress):
        return self.tbl.make_key([
            gc.KeyTuple('meta.egress', hfEgress),
        ])

    def make_data_forward_local_ipv4(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_local_ipv4")

    def make_data_forward_remote_ipv4(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_remote_ipv4")

    def entry_add_forward_local_ipv4(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_local_ipv4(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_add_forward_remote_ipv4(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_remote_ipv4(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_forward_local_ipv6(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_local_ipv6")

    def make_data_forward_remote_ipv6(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_remote_ipv6")

    def entry_add_forward_local_ipv6(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_local_ipv6(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_add_forward_remote_ipv6(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_remote_ipv6(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblSetLocalSource(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblSetLocalSource,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_set_local_source")

    def make_key(self, egressPort):
        return self.tbl.make_key([
            gc.KeyTuple('ig_tm_md.ucast_egress_port', egressPort),
        ])

    def make_data_set_local_source_ipv4(self, srcIp, srcMAC, srcPort):
        return self.tbl.make_data([
            gc.DataTuple('srcIp', srcIp),
            gc.DataTuple('srcMAC', srcMAC),
            gc.DataTuple('srcPort', srcPort),
        ], "set_local_source_ipv4")

    def entry_add_ipv4(self, egressPort, srcIp, srcMAC, srcPort):
        key = self.make_key(egressPort)
        data = self.make_data_set_local_source_ipv4(srcIp, srcMAC, srcPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_set_local_source_ipv6(self, srcIp, srcMAC, srcPort):
        return self.tbl.make_data([
            gc.DataTuple('srcIp', srcIp),
            gc.DataTuple('srcMAC', srcMAC),
            gc.DataTuple('srcPort', srcPort),
        ], "set_local_source_ipv6")

    def entry_add_ipv6(self, egressPort, srcIp, srcMAC, srcPort):
        key = self.make_key(egressPort)
        data = self.make_data_set_local_source_ipv6(srcIp, srcMAC, srcPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])
