// SPDX-License-Identifier: BSD-3-Clause AND AGPL-3.0-or-later

/* -*- P4_16 -*- */

/* 
 * Copyright (c) 2021, SIDN Labs
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined DISABLE_IPV4 && defined DISABLE_IPV6
#error "Disabling both IPv4 and IPv6 support is not supported"
#endif

#include <core.p4>
#include <tna.p4>

#include "headers/common.p4"
#include "scion/headers.p4"
#include "bridge/parser.p4"


/*************************************************************************
*********************** C O N S T A N T S  *******************************
*************************************************************************/

#if __TARGET_TOFINO__ == 1
#define PORT_CPU 64
#define RECIRC_PORT_1 68
#elif __TARGET_TOFINO__ == 2
#define PORT_CPU 130
#define RECIRC_PORT_1 132
#endif
#define MAX_SCION_HF_CNT 8
#define MAX_SCION_HDR_LEN 255           // 1020/4
#define SCION_COMMON_HDR_LEN 3          // 12/4
#define SCION_ADDR_COMMON_HDR_LEN 4     // 16/4
#define SCION_PATH_META_LEN 1           // 4/4
#define SCION_INFO_LEN 2                // 8/4
#define SCION_HOP_LEN 3                 // 12/4

/*************************************************************************
************************* H E A D E R S  *********************************
*************************************************************************/

header scion_cpu_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}


struct header_t {
    scion_cpu_t		scion_cpu;
    ethernet_t		ethernet;
    bridge_t        bridge;
    bridge_after_aes_t bridge_after_aes;
    ethernet_t      secondEthernet;
#ifndef DISABLE_IPV4
    ipv4_t			ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
    ipv6_t			ipv6;
#endif /* DISABLE_IPV6 */
    udp_t			udp;
    scion_common_t		scion_common;
    scion_addr_common_t	scion_addr_common;
    scion_addr_host_32_t	scion_addr_dst_host_32;
    scion_addr_host_32_t	scion_addr_dst_host_32_2;
    scion_addr_host_32_t	scion_addr_dst_host_32_3;
    scion_addr_host_128_t	scion_addr_dst_host_128;
    scion_addr_host_32_t	scion_addr_src_host_32;
    scion_addr_host_32_t	scion_addr_src_host_32_2;
    scion_addr_host_32_t	scion_addr_src_host_32_3;
    scion_addr_host_128_t	scion_addr_src_host_128;
    scion_path_epic_t	scion_epic;
    scion_path_meta_t	scion_path_meta;
    scion_info_field_t	scion_info_field_0;
    scion_info_field_t	scion_info_field_1;
    scion_info_field_t	scion_info_field_2;
    scion_hop_field_t	scion_hop_0;
    scion_hop_field_t	scion_hop_1;
    scion_hop_field_t	scion_hop_2;
    scion_hop_field_t	scion_hop_3;
    scion_hop_field_t	scion_hop_4;
    scion_hop_field_t	scion_hop_5;
    scion_hop_field_t	scion_hop_6;
    scion_hop_field_t	scion_hop_7;
    scion_hop_field_t scion_hop_field_0;
    scion_hop_field_t scion_hop_field_1;
    scion_hop_by_hop_opt_t  scion_hop_by_hop;
}

struct metadata_t {
    bit<8>  nextHdr;
    bit<8>	currHF;
    bit<8>	currHF2;
    bit<8>  nextHF;
    bit<1>	direction;
    bit<1>  skipScion;
    bit<6>	segLen;
    bit<1>  recirculation;
    bit<16> segId;
    bit<16> nextSegId;
    bit<16> ingress;
    bit<16> egress;
    bit<2>	nextINF;
    bit<6>	seg1Len;
    bit<16>	udp_checksum_tmp;
    bit<16> payload_len;
    bit<32> hvf;
    bit<2>  cc;
}

/*************************************************************************
***********************  P A R S E R  ************************************
*************************************************************************/

parser ScionIngressParser(
        packet_in packet,
        out header_t hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md
)
{
    Checksum() udp_checksum;
    ParserCounter() hf_counter;
    
    BridgeParser() bridge_parser;

    state start {
        // Extract metadata and skip over recirculation info
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            EtherType.BRIDGE: bridge_main;
#ifndef DISABLE_IPV4
            EtherType.IPV4: ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
            EtherType.IPV6: ipv6;
#endif /* DISABLE_IPV6 */
        }
    }
    
    // Extract bridge header used for MAC calculation on external device
    state bridge_main {
        bridge_parser.apply(packet, hdr.bridge_after_aes);
        
        transition secondEthernet;
    }
    
    state secondEthernet {
        packet.extract(hdr.secondEthernet);
        
        transition select(hdr.secondEthernet.etherType) {
#ifndef DISABLE_IPV4
            EtherType.IPV4: ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
            EtherType.IPV6: ipv6;
#endif /* DISABLE_IPV6 */
        }
    }

#ifndef DISABLE_IPV4
    state ipv4 {
        packet.extract(hdr.ipv4);

        udp_checksum.subtract({hdr.ipv4.srcAddr});
        udp_checksum.subtract({hdr.ipv4.dstAddr});

        transition scion;
    }
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
    state ipv6 {
        packet.extract(hdr.ipv6);
        udp_checksum.subtract({hdr.ipv6.srcAddr});
        udp_checksum.subtract({hdr.ipv6.dstAddr});
        transition scion;
    }
#endif /* DISABLE_IPV6 */
    
    state scion {
        packet.extract(hdr.udp);
        udp_checksum.subtract({hdr.udp.srcPort, hdr.udp.dstPort});
        udp_checksum.subtract({hdr.udp.checksum});

        packet.extract(hdr.scion_common);
        packet.extract(hdr.scion_addr_common);
        
        meta.nextHdr = hdr.scion_common.nextHdr;
        meta.currHF = 0;

        transition select(hdr.scion_common.dl, hdr.scion_common.sl) {
            (0, 0): addr_dst_src_host_32_32;
            (0, 1): addr_dst_src_host_32_64;
            (0, 2): addr_dst_src_host_32_96;
            (0, 3): addr_dst_src_host_32_128;
            (1, 0): addr_dst_src_host_64_32;
            (1, 1): addr_dst_src_host_64_64;
            (1, 2): addr_dst_src_host_64_96;
            (1, 3): addr_dst_src_host_64_128;
            (2, 0): addr_dst_src_host_96_32;
            (2, 1): addr_dst_src_host_96_64;
            (2, 2): addr_dst_src_host_96_96;
            (2, 3): addr_dst_src_host_96_128;
            (3, 0): addr_dst_src_host_128_32;
            (3, 1): addr_dst_src_host_128_64;
            (3, 2): addr_dst_src_host_128_96;
            (3, 3): addr_dst_src_host_128_128;
        }
    }

    state addr_dst_src_host_32_32 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_src_host_32);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(2);

        transition path;
    }

    state addr_dst_src_host_32_64 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(3);

        transition path;
    }

    state addr_dst_src_host_32_96 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32_3);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(4);

        transition path;
    }

    state addr_dst_src_host_32_128 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_src_host_128);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(5);

        transition path;
    }

    state addr_dst_src_host_64_32 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(3);

        transition path;
    }

    state addr_dst_src_host_64_64 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(4);

        transition path;
    }

    state addr_dst_src_host_64_96 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32_3);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(5);

        transition path;
    }

    state addr_dst_src_host_64_128 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_src_host_128);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(6);

        transition path;
    }

    state addr_dst_src_host_96_32 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_dst_host_32_3);
        packet.extract(hdr.scion_addr_src_host_32);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(4);

        transition path;
    }

    state addr_dst_src_host_96_64 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_dst_host_32_3);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(5);

        transition path;
    }

    state addr_dst_src_host_96_96 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_dst_host_32_3);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32_3);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(6);
    
        transition path;
    }

    state addr_dst_src_host_96_128 {
        packet.extract(hdr.scion_addr_dst_host_32);
        packet.extract(hdr.scion_addr_dst_host_32_2);
        packet.extract(hdr.scion_addr_dst_host_32_3);
        packet.extract(hdr.scion_addr_src_host_128);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(7);

        transition path;
    }

    state addr_dst_src_host_128_32 {
        packet.extract(hdr.scion_addr_dst_host_128);
        packet.extract(hdr.scion_addr_src_host_32);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(5);

        transition path;
    }

    state addr_dst_src_host_128_64 {
        packet.extract(hdr.scion_addr_dst_host_128);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(6);

        transition path;
    }

    state addr_dst_src_host_128_96 {
        packet.extract(hdr.scion_addr_dst_host_128);
        packet.extract(hdr.scion_addr_src_host_32);
        packet.extract(hdr.scion_addr_src_host_32_2);
        packet.extract(hdr.scion_addr_src_host_32_3);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(7);

        transition path;
    }

    state addr_dst_src_host_128_128 {
        packet.extract(hdr.scion_addr_dst_host_128);
        packet.extract(hdr.scion_addr_src_host_128);
        
        hf_counter.set(hdr.scion_common.hdrLen);
        hf_counter.decrement(SCION_COMMON_HDR_LEN);
        hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN);
        hf_counter.decrement(8);
        
        transition path;
    }

    state path {
        transition select(hdr.scion_common.pathType) {
            PathType.EMPTY: accept;
            PathType.SCION: path_scion;
            PathType.EPIC: path_epic;
            PathType.ONEHOP: path_onehop;
            // Other path types are not supported
        }
    }

    state path_epic {
        packet.extract(hdr.scion_epic);
        hf_counter.decrement(16);
        transition path_scion;
    }
    
    state path_onehop {
        packet.extract(hdr.scion_info_field_0);
        
        hf_counter.decrement(SCION_INFO_LEN);
        
        transition extract_current_hop_field_0;
    }

    state path_scion {
        packet.extract(hdr.scion_path_meta);
        udp_checksum.subtract({hdr.scion_path_meta.currInf, hdr.scion_path_meta.currHF, hdr.scion_path_meta.rsv, hdr.scion_path_meta.seg0Len, hdr.scion_path_meta.seg1Len, hdr.scion_path_meta.seg2Len});
        
        hf_counter.decrement(SCION_PATH_META_LEN);
        meta.currHF = (bit<8>)hdr.scion_path_meta.currHF;

        // We assume there is at least one info field present
        transition select(hdr.scion_path_meta.seg1Len, hdr.scion_path_meta.seg2Len) {
            (0, 0): info_field_0;
            (_, 0): info_field_1;
            default: info_field_2;
        }		
    }

    state info_field_0 {
        packet.extract(hdr.scion_info_field_0);
        udp_checksum.subtract({hdr.scion_info_field_0.segId});
        
        hf_counter.decrement(SCION_INFO_LEN);

        hdr.scion_info_field_1.segId = 0;
        hdr.scion_info_field_2.segId = 0;

        transition select_current_hop_field;
    }

    state info_field_1 {
        packet.extract(hdr.scion_info_field_0);
        udp_checksum.subtract({hdr.scion_info_field_0.segId});
        packet.extract(hdr.scion_info_field_1);
        udp_checksum.subtract({hdr.scion_info_field_1.segId});
        
        hf_counter.decrement(2 * SCION_INFO_LEN);

        hdr.scion_info_field_2.segId = 0;

        transition select_current_hop_field;
    }

    state info_field_2 {
        packet.extract(hdr.scion_info_field_0);
        udp_checksum.subtract({hdr.scion_info_field_0.segId});
        packet.extract(hdr.scion_info_field_1);
        udp_checksum.subtract({hdr.scion_info_field_1.segId});
        packet.extract(hdr.scion_info_field_2);
        udp_checksum.subtract({hdr.scion_info_field_2.segId});
        
        hf_counter.decrement(3 * SCION_INFO_LEN);

        transition select_current_hop_field;
    }
    
    state select_current_hop_field {
        transition select(hdr.scion_path_meta.currHF) {
            0: extract_current_hop_field_0;
            1: extract_current_hop_field_1;
            2: extract_current_hop_field_2;
            3: extract_current_hop_field_3;
            4: extract_current_hop_field_4;
            5: extract_current_hop_field_5;
            6: extract_current_hop_field_6;
            7: extract_current_hop_field_7;
        }
    }

    state extract_current_hop_field_0 {
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_0);
        
        hf_counter.decrement(2 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_1;
            default: accept;
        }
    }
    
    state extract_next_hop_field_1 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_1);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_2;
            default: accept;
        }
    }
    
    state extract_other_hop_fields_2 {
        packet.extract(hdr.scion_hop_2);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_3;
            default: accept;
        }
    }
    
    state extract_current_hop_field_1 {
        packet.extract(hdr.scion_hop_0);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_1);
        
        hf_counter.decrement(3 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_2;
            default: accept;
        }
    }
    
    state extract_next_hop_field_2 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_2);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_3;
            default: accept;
        }
    }
    
    state extract_other_hop_fields_3 {
        packet.extract(hdr.scion_hop_3);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_4;
            default: accept;
        }
    }
    
    state extract_current_hop_field_2 {
        packet.extract(hdr.scion_hop_0);
        packet.extract(hdr.scion_hop_1);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_2);
        
        hf_counter.decrement(4 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_3;
            default: accept;
        }
    }
    
    state extract_next_hop_field_3 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_3);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_4;
            default: accept;
        }
    }
    
    state extract_other_hop_fields_4 {
        packet.extract(hdr.scion_hop_4);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_5;
            default: accept;
        }
    }
    
    state extract_current_hop_field_3 {
        packet.extract(hdr.scion_hop_0);
        packet.extract(hdr.scion_hop_1);
        packet.extract(hdr.scion_hop_2);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_3);
        
        hf_counter.decrement(5 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_4;
            default: accept;
        }
    }
    
    state extract_next_hop_field_4 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_4);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_5;
            default: accept;
        }
    }
    
    state extract_other_hop_fields_5 {
        packet.extract(hdr.scion_hop_5);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_6;
            default: accept;
        }
    }
    
    state extract_current_hop_field_4 {
        packet.extract(hdr.scion_hop_0);
        packet.extract(hdr.scion_hop_1);
        packet.extract(hdr.scion_hop_2);
        packet.extract(hdr.scion_hop_3);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_4);
        
        hf_counter.decrement(6 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_5;
            default: accept;
        }
    }
    
    state extract_next_hop_field_5 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_5);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_6;
            default: accept;
        }
    }
    
    state extract_other_hop_fields_6 {
        packet.extract(hdr.scion_hop_6);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_7;
            default: accept;
        }
    }
    
    state extract_current_hop_field_5 {
        packet.extract(hdr.scion_hop_0);
        packet.extract(hdr.scion_hop_1);
        packet.extract(hdr.scion_hop_2);
        packet.extract(hdr.scion_hop_3);
        packet.extract(hdr.scion_hop_4);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_5);
        
        hf_counter.decrement(7 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_6;
            default: accept;
        }
    }
    
    state extract_next_hop_field_6 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_6);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_other_hop_fields_7;
            default: accept;
        }
    }
    
    state extract_other_hop_fields_7 {
        packet.extract(hdr.scion_hop_7);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            true: accept;
        }
    }
    
    state extract_current_hop_field_6 {
        packet.extract(hdr.scion_hop_0);
        packet.extract(hdr.scion_hop_1);
        packet.extract(hdr.scion_hop_2);
        packet.extract(hdr.scion_hop_3);
        packet.extract(hdr.scion_hop_4);
        packet.extract(hdr.scion_hop_5);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_6);
        
        hf_counter.decrement(8 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            false: extract_next_hop_field_7;
            default: accept;
        }
    }
    
    state extract_next_hop_field_7 {
        hdr.scion_hop_field_1 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_7);
        
        hf_counter.decrement(SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            true: accept;
        }
    }
    
    state extract_current_hop_field_7 {
        packet.extract(hdr.scion_hop_0);
        packet.extract(hdr.scion_hop_1);
        packet.extract(hdr.scion_hop_2);
        packet.extract(hdr.scion_hop_3);
        packet.extract(hdr.scion_hop_4);
        packet.extract(hdr.scion_hop_5);
        packet.extract(hdr.scion_hop_6);
        
        hdr.scion_hop_field_0 = packet.lookahead<scion_hop_field_t>();
        packet.extract(hdr.scion_hop_7);
        
        hf_counter.decrement(9 * SCION_HOP_LEN);
        
        transition select(hf_counter.is_negative()) {
            true: accept;
        }
    }
    
    state check_for_extension {
        transition select(meta.nextHdr) {
            200: scion_hop_by_hop;
            default: accept;
        }
    }

    state scion_hop_by_hop {
        packet.extract(hdr.scion_hop_by_hop);
        
        transition accept;
    }
}

parser ScionEgressParser(
        packet_in packet,
        out header_t hdr,
        out metadata_t meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        transition accept;
    }
}

/*************************************************************************
**************  I N G R E S S	P R O C E S S I N G	*******************
*************************************************************************/


control ScionIngressControl(
        inout header_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    action send_to_cpu() {
        hdr.scion_cpu.setValid();
        hdr.scion_cpu.srcAddr = (bit<48>)ig_intr_md.ingress_port;
        hdr.scion_cpu.dstAddr = 0xffffffffffff;
        hdr.scion_cpu.etherType = 0x5C10;
        ig_tm_md.ucast_egress_port = PORT_CPU;
    }
    
    // Define action selector to support balancing load between multiple external accelerators
	Hash<bit<29>>(HashAlgorithm_t.CRC16) lag_ecmp_hash;
	ActionProfile(size=8192) lag_ecmp;
	ActionSelector(action_profile = lag_ecmp,
	               hash = lag_ecmp_hash,
	               mode = SelectorMode_t.FAIR,
	               max_group_size = 1024,
	               num_groups = 1024) lag_ecmp_sel;

    action drop() {
        // Mark to drop
        ig_dprsr_md.drop_ctl = 1;
    }
    
    // Initialize the bridge header
    action create_bridge_hdr(PortId_t port, macAddr_t dst, macAddr_t src) {
        // Set new data to second ethernet header to prevent from changing these data by other code fragments
        hdr.secondEthernet.dstAddr = dst;
        hdr.secondEthernet.srcAddr = src;
        
        // Create Bridge header
        hdr.bridge.main.checkFirstHf = 0;
        hdr.bridge.main.checkSecHf = 0;
        hdr.bridge.main.cryptCounter = 0;
        hdr.bridge.main.rsv = 0;
        hdr.bridge.main.len = 0;
        ig_tm_md.ucast_egress_port = port;
        hdr.bridge.main.egressPort = port;
        hdr.bridge.main.switchData = 0;
    }
    
    // Select the accelerator that should be used
	table tbl_select_accelerator {
	    key = {
	        ig_intr_md.ingress_port: ternary;
            hdr.scion_common.payloadLen: selector;
            hdr.scion_addr_common.dstAS: selector;
            hdr.scion_addr_common.srcAS: selector;
            hdr.scion_hop_field_0.inIf: selector;
            hdr.scion_hop_field_0.egIf: selector;
	    }
	    actions = {
	        create_bridge_hdr;
        }
        size = 2560;
        implementation = lag_ecmp_sel;
	}
    
    action update_bridge_ethernet() {
        // Save the ethernet data for exchange
        macAddr_t dstAddr = hdr.secondEthernet.dstAddr;
        macAddr_t srcAddr = hdr.secondEthernet.srcAddr;
        
        // Move original ethernet header to the second ethernet header
        hdr.secondEthernet.dstAddr = hdr.ethernet.dstAddr;
        hdr.secondEthernet.srcAddr = hdr.ethernet.srcAddr;
        hdr.secondEthernet.etherType = hdr.ethernet.etherType;
        
        // Alter the first ethernet header to bridge ethernet header
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.etherType = EtherType.BRIDGE;
    }

#ifndef DISABLE_IPV4
    action initialise_ipv4() {
        hdr.ipv4.setValid();
#ifndef DISABLE_IPV6
        hdr.ipv6.setInvalid();
#endif /* DISABLE_IPV6 */
        hdr.ethernet.etherType = EtherType.IPV4;

        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = meta.payload_len + 20;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = Proto.UDP;
        // Next fields are set in other functions
        //hdr.ipv4.hdrChecksum
        //hdr.ipv4.srcAddr
        //hdr.ipv4.dstAddr
    }
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
    action initialise_ipv6() {
        hdr.ipv6.setValid();
#ifndef DISABLE_IPV4
        hdr.ipv4.setInvalid();
#endif /* DISABLE_IPV4 */

        hdr.ethernet.etherType = EtherType.IPV6;

        hdr.ipv6.version = 6;
        hdr.ipv6.trafficClass = 0;
        hdr.ipv6.flowLabel = 0;
        hdr.ipv6.payloadLen = meta.payload_len;
        hdr.ipv6.nextHdr = Proto.UDP;
        hdr.ipv6.hopLimit = 64;
        // Next fields are set in other functions
        //hdr.ipv6.srcAddr
        //hdr.ipv6.dstAddr
    }
#endif /* DISABLE_IPV6 */

    // Verify the port we received the packet on is the one we expected it on
    table tbl_ingress_verification {
        key = {
            meta.ingress: exact;
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }
    
    // Insert key into bridge header
    action insert_bridge_key(bit<32> key1, bit<32> key2, bit<32> key3, bit<32> key4) {
        hdr.bridge.key.key0 = key1;
        hdr.bridge.key.key1 = key2;
        hdr.bridge.key.key2 = key3;
        hdr.bridge.key.key3 = key4;
    }

    table tbl_bridge_key {
        key = {
            hdr.scion_common.version: exact;
        }
        actions = {
            drop;
            insert_bridge_key;
        }
        size = 64;
        default_action = drop;
    }

    // XOR first hop field with subkey
    action bridge_subkey_hop1(bit<16> key1, bit<16> key2, bit<32> key3, bit<8> key4, bit<8> key5, bit<16> key6, bit<16> key7, bit<16> key8) {
        hdr.bridge.hop_field_1.bridge_fields.rsv = hdr.bridge.hop_field_1.bridge_fields.rsv ^ key1;
        hdr.bridge.hop_field_1.bridge_fields.beta = hdr.bridge.hop_field_1.bridge_fields.beta ^ key2;
        hdr.bridge.hop_field_1.bridge_fields.timestamp = hdr.bridge.hop_field_1.bridge_fields.timestamp ^ key3;
        hdr.bridge.hop_field_1.hop_field.routerAlerts = hdr.bridge.hop_field_1.hop_field.routerAlerts ^ key4;
        hdr.bridge.hop_field_1.hop_field.expTime = hdr.bridge.hop_field_1.hop_field.expTime ^ key5;
        hdr.bridge.hop_field_1.hop_field.inIf = hdr.bridge.hop_field_1.hop_field.inIf ^ key6;
        hdr.bridge.hop_field_1.hop_field.egIf = hdr.bridge.hop_field_1.hop_field.egIf ^ key7;
        hdr.bridge.hop_field_1.hop_field.reserved = hdr.bridge.hop_field_1.hop_field.reserved ^ key8;
    }

    // XOR second hop field with subkey
    action bridge_subkey_hop2(bit<16> key1, bit<16> key2, bit<32> key3, bit<8> key4, bit<8> key5, bit<16> key6, bit<16> key7, bit<16> key8) {
        bridge_subkey_hop1(key1, key2, key3, key4, key5, key6, key7, key8);
        hdr.bridge.hop_field_2.bridge_fields.rsv = hdr.bridge.hop_field_2.bridge_fields.rsv ^ key1;
        hdr.bridge.hop_field_2.bridge_fields.beta = hdr.bridge.hop_field_2.bridge_fields.beta ^ key2;
        hdr.bridge.hop_field_2.bridge_fields.timestamp = hdr.bridge.hop_field_2.bridge_fields.timestamp ^ key3;
        hdr.bridge.hop_field_2.hop_field.routerAlerts = hdr.bridge.hop_field_2.hop_field.routerAlerts ^ key4;
        hdr.bridge.hop_field_2.hop_field.expTime = hdr.bridge.hop_field_2.hop_field.expTime ^ key5;
        hdr.bridge.hop_field_2.hop_field.inIf = hdr.bridge.hop_field_2.hop_field.inIf ^ key6;
        hdr.bridge.hop_field_2.hop_field.egIf = hdr.bridge.hop_field_2.hop_field.egIf ^ key7;
        hdr.bridge.hop_field_2.hop_field.reserved = hdr.bridge.hop_field_2.hop_field.reserved ^ key8;
    }

    // Check whether one or two hop fields have to be XORed
    table tbl_bridge_subkey {
        key = {
            meta.recirculation: exact;
        }
        actions = {
            drop;
            bridge_subkey_hop1;
            bridge_subkey_hop2;
        }
        size = 2;
        default_action = drop;
    }
    
    // Create the first bridge hop field
    action create_bridge_hop_1(scion_info_field_t info_field, scion_hop_field_t scion_hop_field) {
        hdr.bridge.hop_field_1.bridge_fields.rsv = 0;
        hdr.bridge.hop_field_1.bridge_fields.beta = meta.segId;
        hdr.bridge.hop_field_1.bridge_fields.timestamp = info_field.timestamp;
        hdr.bridge.hop_field_1.hop_field.routerAlerts = 0;
        hdr.bridge.hop_field_1.hop_field.inIf = scion_hop_field.inIf;
        hdr.bridge.hop_field_1.hop_field.egIf = scion_hop_field.egIf;
        hdr.bridge.hop_field_1.hop_field.expTime = scion_hop_field.expTime;
    }
    
    // Create the second bridge hop field
    action create_bridge_hop_2(scion_info_field_t info_field, scion_hop_field_t scion_hop_field) {
        hdr.bridge.hop_field_2.bridge_fields.rsv = 0;
        hdr.bridge.hop_field_2.bridge_fields.beta = info_field.segId;
        hdr.bridge.hop_field_2.bridge_fields.timestamp = info_field.timestamp;
        hdr.bridge.hop_field_2.hop_field.routerAlerts = 0;
        hdr.bridge.hop_field_2.hop_field.inIf = scion_hop_field.inIf;
        hdr.bridge.hop_field_2.hop_field.egIf = scion_hop_field.egIf;
        hdr.bridge.hop_field_2.hop_field.expTime = scion_hop_field.expTime;
    }
    
    // Create SCION hop field for one-hop packets addressed to this AS and add bridge field for MAC calculation
    action set_ingress_interface(bit<16> inIf) {
        hdr.scion_hop_1.routerAlerts = 0;
        hdr.scion_hop_1.expTime = 63; //TODO: Make configurable?
        hdr.scion_hop_1.inIf = inIf;
        hdr.scion_hop_1.egIf = 0;
        create_bridge_hop_1(hdr.scion_info_field_0, hdr.scion_hop_1);
    }

    action calc_next_hf(){
        meta.nextHF = meta.currHF+1;
    }
    
    // Check, which interface matches to the ingress port (one-hop packets addressed to this AS)
    table tbl_ingress_interface {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            NoAction;
            set_ingress_interface;
        }
        size = 64;
        default_action = NoAction;
    }

    // Check whether a packet is destined for the current ISD/AS
    table tbl_check_local {
        key = {
            hdr.scion_addr_common.dstISD: exact;
            hdr.scion_addr_common.dstAS: exact;
        }
        actions = {
            NoAction;
        }
        size = 1;
        default_action = NoAction;
    }
    
    // Check, if the path to the remote destination is up according to BFD protocol
    table tbl_bfd_remote {
        key = {
            meta.egress: exact;
        }
        actions = {
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }


    // Check, if the local path is down according to BFD protocol
    table tbl_bfd_local {
        key = {
            hdr.scion_common.dl: exact;
            hdr.scion_common.dt: exact;
            hdr.scion_addr_dst_host_32.host: ternary;
            hdr.scion_addr_dst_host_128.host: ternary;
        }
        actions = {
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

#ifndef DISABLE_IPV4
    action deliver_local_ipv4(PortId_t port, bit<48> dstMAC, bit<16> dstPort) {
        ig_tm_md.ucast_egress_port = port;

        initialise_ipv4();
        hdr.ipv4.dstAddr = hdr.scion_addr_dst_host_32.host;

        hdr.ethernet.dstAddr = dstMAC;
        hdr.udp.dstPort = dstPort;
    }

    action deliver_local_service_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        ig_tm_md.ucast_egress_port = port;

        initialise_ipv4();
        hdr.ipv4.dstAddr = dstIP;

        hdr.udp.dstPort = dstPort;
        hdr.ethernet.dstAddr = dstMAC;
    }
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
    action deliver_local_ipv6(PortId_t port, bit<48> dstMAC, bit<16> dstPort) {
        ig_tm_md.ucast_egress_port = port;

        initialise_ipv6();
        hdr.ipv6.dstAddr = hdr.scion_addr_dst_host_128.host;

        hdr.ethernet.dstAddr = dstMAC;
        hdr.udp.dstPort = dstPort;
    }

    action deliver_local_service_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        ig_tm_md.ucast_egress_port = port;

        initialise_ipv6();
        hdr.ipv6.dstAddr = dstIP;

        hdr.udp.dstPort = dstPort;
        hdr.ethernet.dstAddr = dstMAC;
    }
#endif /* DISABLE_IPV6 */

    // Determine egress port and destination address (IP and/or MAC) for local bound traffic
    table tbl_deliver_local {
        key = {
            hdr.scion_common.dl: exact;
            hdr.scion_common.dt: exact;
            hdr.scion_addr_dst_host_32.host: ternary;
            hdr.scion_addr_dst_host_128.host: ternary;
        }
        actions = {
#ifndef DISABLE_IPV4
            deliver_local_ipv4;
            deliver_local_service_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
            deliver_local_ipv6;
            deliver_local_service_ipv6;
#endif /* DISABLE_IPV6 */
            @defaultonly drop;
        }
        size = 16;
        default_action = drop();
    }
    
    // Determine egress port and destination address (IP and/or MAC) for traffic inside one AS
    table tbl_deliver_local_empty {
        key = {
            hdr.scion_common.dl: exact;
            hdr.scion_common.dt: exact;
            hdr.scion_addr_dst_host_32.host: ternary;
            hdr.scion_addr_dst_host_128.host: ternary;
        }
        actions = {
#ifndef DISABLE_IPV4
            deliver_local_ipv4;
            deliver_local_service_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
            deliver_local_ipv6;
            deliver_local_service_ipv6;
#endif /* DISABLE_IPV6 */
            @defaultonly drop;
        }
        size = 16;
        default_action = drop();
    }

#ifndef DISABLE_IPV4
    action set_local_source_ipv4(bit<32> srcIp, bit<48> srcMAC, bit<16> srcPort) {
        hdr.ethernet.srcAddr = srcMAC;

        hdr.ipv4.srcAddr = srcIp;

        hdr.udp.srcPort = srcPort;
        hdr.udp.checksum = 0;
    }
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
    action set_local_source_ipv6(bit<128> srcIp, bit<48> srcMAC, bit<16> srcPort) {
        hdr.ethernet.srcAddr = srcMAC;

        hdr.ipv6.srcAddr = srcIp;

        hdr.udp.srcPort = srcPort;
        hdr.udp.checksum = 0;
        // Required checksum for IPv6 is computed in deparser
    }
#endif /* DISABLE_IPV6 */

    // Set the source IP/MAC address based on the egress port
    // We currently allow one IP and MAC per port, but it could be extended if we let it depend on the egress in the header as well. If we use ternary matching for this, it can be used only if desired
    table tbl_set_local_source {
        key = {
            ig_tm_md.ucast_egress_port: exact;
        }
        actions = {
#ifndef DISABLE_IPV4
            set_local_source_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
            set_local_source_ipv6;
#endif /* DISABLE_IPV6 */
            @defaultonly drop;
        }
        size = 64;
        default_action = drop();
     }

#ifndef DISABLE_IPV4
    action forward_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        ig_tm_md.ucast_egress_port = port;

        initialise_ipv4();
        hdr.ipv4.dstAddr = dstIP;

        hdr.ethernet.dstAddr = dstMAC;
        hdr.udp.dstPort = dstPort;
    }

    action forward_remote_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        forward_ipv4(port, dstIP, dstMAC, dstPort);
    }

    action forward_local_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        forward_ipv4(port, dstIP, dstMAC, dstPort);
    }
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
    action forward_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        ig_tm_md.ucast_egress_port = port;

        initialise_ipv6();
        hdr.ipv6.dstAddr = dstIP;

        hdr.ethernet.dstAddr = dstMAC;
        hdr.udp.dstPort = dstPort;
    }

    action forward_remote_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        forward_ipv6(port, dstIP, dstMAC, dstPort);
    }

    action forward_local_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
        forward_ipv6(port, dstIP, dstMAC, dstPort);
    }
#endif /* DISABLE_IPV6 */

    // Determine where to forward packet to based on SCION egress interface 
    table tbl_forward {
        key = {
            meta.egress: exact;
        }
        actions = {
#ifndef DISABLE_IPV4
            forward_remote_ipv4;
            forward_local_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
            forward_remote_ipv6;
            forward_local_ipv6;
#endif /* DISABLE_IPV6 */
            @defaultonly drop;
        }
        size = 64;
        default_action = drop();
    }

    apply {
        meta.currHF = meta.currHF & 0x3f;
        if (ig_prsr_md.parser_err != PARSER_ERROR_OK) {
            drop();
            exit;
        }

        bool local_destination = tbl_check_local.apply().hit;
        meta.skipScion = 0;
        meta.recirculation = 0;

        meta.cc = hdr.bridge_after_aes.main.cryptCounter;
        @in_hash{meta.cc = meta.cc+1;}
        
        if (hdr.bridge_after_aes.main.isValid() && (hdr.bridge_after_aes.main.cryptCounter == 2)) {
            // Set all bridge headers invalid
            hdr.ethernet.setInvalid();
            hdr.bridge.main.setInvalid();
            hdr.bridge_after_aes.main.setInvalid();
            hdr.bridge_after_aes.bridge_aes_1.setInvalid();
            hdr.bridge_after_aes.bridge_aes_2.setInvalid();
            hdr.bridge_after_aes.original_key.setInvalid();
            hdr.bridge_after_aes.key_copy.setInvalid();
            hdr.bridge.hop_field_1.bridge_fields.setInvalid();
            hdr.bridge.hop_field_1.hop_field.setInvalid();
            hdr.bridge.hop_field_2.bridge_fields.setInvalid();
            hdr.bridge.hop_field_2.hop_field.setInvalid();
            hdr.bridge.key.setInvalid();
            meta.skipScion = 1;

            ig_tm_md.ucast_egress_port = hdr.bridge_after_aes.main.egressPort;
        }
        bool skip_processing = false;
        if (meta.skipScion == 0) {
            if (hdr.scion_common.pathType != PathType.EMPTY) {
                meta.seg1Len = hdr.scion_path_meta.seg1Len;
            }
            if (hdr.ipv4.isValid()) {
                meta.payload_len = hdr.ipv4.totalLen - 20;
            }

            if(hdr.scion_common.pathType == PathType.SCION || hdr.scion_common.pathType == PathType.EPIC) {
                // Update metadata fields based on the currently selected info field
                if (hdr.scion_path_meta.currInf == 0) {
                    meta.direction = hdr.scion_info_field_0.direction;
                    meta.segId = hdr.scion_info_field_0.segId;
                    @in_hash{ meta.segLen = hdr.scion_path_meta.seg0Len; }
                    meta.nextINF = 1;
                } else if (hdr.scion_path_meta.seg1Len > 0 && hdr.scion_path_meta.currInf == 1) {
                    meta.direction = hdr.scion_info_field_1.direction;
                    meta.segId = hdr.scion_info_field_1.segId;
                    @in_hash{ meta.segLen = hdr.scion_path_meta.seg0Len + meta.seg1Len; }
                    meta.nextINF = 2;
                } else if (hdr.scion_path_meta.seg2Len > 0 && hdr.scion_path_meta.currInf == 2) {
                    meta.direction = hdr.scion_info_field_2.direction;
                    meta.segId = hdr.scion_info_field_2.segId;
                    @in_hash{ meta.segLen = 0; } // Not relevant (and incorrect). This should make sure currInf is not updated
                    meta.nextINF = 2;
                } else {
                    // Drop and exit
                    drop();
                    exit;
                }
            }

            if (hdr.scion_common.pathType == PathType.EPIC && hdr.bridge_after_aes.main.isValid()) {
                bit<8> segLenReduced;
                @in_hash{segLenReduced=(bit<8>)meta.segLen;}
                segLenReduced = segLenReduced - 1;
                calc_next_hf();
            
                if (meta.currHF == segLenReduced) {
                    meta.hvf = hdr.scion_epic.lhvf;
                    meta.skipScion = 1;
                }
                if (meta.nextHF == segLenReduced) {
                    meta.hvf = hdr.scion_epic.phvf;
                    meta.skipScion = 1;
                }
            } else if (hdr.bridge_after_aes.main.isValid()){
                meta.skipScion = 1;
            }
        }

        if (meta.skipScion == 0) {
            if(hdr.scion_common.pathType == PathType.SCION || hdr.scion_common.pathType == PathType.EPIC) {            
                // Enable MAC validation for all non-BFD packets
                if (hdr.scion_common.nextHdr != 0xCB && !hdr.bridge_after_aes.main.isValid()) {
                    // Create bridge header for MAC validation
                    hdr.bridge.main.setValid();
                    hdr.bridge.key.setValid();

                    tbl_bridge_key.apply();

                    hdr.bridge.hop_field_1.bridge_fields.setValid();
                    hdr.bridge.hop_field_1.hop_field.setValid();
                    hdr.secondEthernet.setValid();

                    tbl_select_accelerator.apply();
                    hdr.bridge.main.checkFirstHf = 1;
                    hdr.bridge.main.checkSecHf = 0;
                }                
                // Check for 2 HFs
                @in_hash{ meta.currHF = meta.currHF + 1; }
                @in_hash{ meta.currHF2 = meta.currHF2 + 1; }
                if ((bit<6>)meta.currHF2 == (bit<6>)meta.segLen && !local_destination) {
                    meta.recirculation = 1;
                }

                // Compute the new segId value for the info field
                meta.nextSegId = meta.segId ^ hdr.scion_hop_field_0.mac[47:32];

                // Depending on the direction indicated in the info field, we need to use the next segId in the MAC computation and reverse the in- and egress interfaces
                if (meta.direction == 0) { // Only for up direction
                    if(hdr.scion_hop_field_0.egIf == 0) {
                        meta.nextSegId = meta.segId;
                    } else {
                        meta.segId = meta.nextSegId;
                    }
                    meta.ingress = hdr.scion_hop_field_0.egIf;
                    meta.egress = hdr.scion_hop_field_0.inIf;
                } else {
                    meta.ingress = hdr.scion_hop_field_0.inIf;
                    meta.egress = hdr.scion_hop_field_0.egIf;
                }

                // Validate MAC
                if (hdr.scion_path_meta.currInf == 0) {
                    create_bridge_hop_1(hdr.scion_info_field_0, hdr.scion_hop_field_0);
                } else if (hdr.scion_path_meta.seg1Len > 0 && hdr.scion_path_meta.currInf == 1) {
                    create_bridge_hop_1(hdr.scion_info_field_1, hdr.scion_hop_field_0);
                } else if (hdr.scion_path_meta.seg2Len > 0 && hdr.scion_path_meta.currInf == 2) {
                    create_bridge_hop_1(hdr.scion_info_field_2, hdr.scion_hop_field_0);
                }

                // Do for second hop field if necessary
                if (meta.recirculation == 1) {
                    // Update the header
                    if (hdr.scion_path_meta.currInf == 0) {
                        hdr.scion_info_field_0.segId = meta.nextSegId;
                    } else if (hdr.scion_path_meta.currInf == 1) {
                        hdr.scion_info_field_1.segId = meta.nextSegId;
                    } else if (hdr.scion_path_meta.currInf == 2) {
                        hdr.scion_info_field_2.segId = meta.nextSegId;
                    }

                    //@in_hash{ hdr.scion_path_meta.currHF = hdr.scion_path_meta.currHF + 1; }
                    hdr.scion_path_meta.currInf = meta.nextINF;

                    // Update metadata fields based on the currently selected info field
                    if (hdr.scion_path_meta.seg1Len > 0 && hdr.scion_path_meta.currInf == 1) {
                        meta.segId = hdr.scion_info_field_1.segId;
                        meta.direction = hdr.scion_info_field_1.direction;
                    } else if (hdr.scion_path_meta.seg2Len > 0 && hdr.scion_path_meta.currInf == 2) {
                        meta.segId = hdr.scion_info_field_2.segId;
                        meta.direction = hdr.scion_info_field_2.direction;
                    } else {
                        // Drop and exit
                        drop();
                        exit;
                    }

                    // Compute the new segId value for the info field
                    meta.nextSegId = meta.segId ^ hdr.scion_hop_field_1.mac[47:32];

                    if (meta.direction == 0) { // Only for up direction
                        if(hdr.scion_hop_field_1.egIf == 0) {
                            meta.nextSegId = meta.segId;
                        } else {
                            meta.segId = meta.nextSegId;
                        }
                        meta.egress = hdr.scion_hop_field_1.inIf;
                    } else {
                        meta.egress = hdr.scion_hop_field_1.egIf;
                    }

                    // Add second hop field for validation
                    hdr.bridge.main.checkSecHf = 1;
                    hdr.bridge.hop_field_2.bridge_fields.setValid();
                    hdr.bridge.hop_field_2.hop_field.setValid();
                    if (hdr.scion_path_meta.currInf == 1) {
                        create_bridge_hop_2(hdr.scion_info_field_1, hdr.scion_hop_field_1);
                    } else if (hdr.scion_path_meta.currInf == 2) {
                        create_bridge_hop_2(hdr.scion_info_field_2, hdr.scion_hop_field_1);
                    }
                }
            } else if(hdr.scion_common.pathType == PathType.ONEHOP) {
                if(local_destination) {
                    if (hdr.scion_common.nextHdr == 0xCB) {
                        // If we receive a BFD packet from another port than CPU we assume it is addressed to this border router
                        send_to_cpu();
                        skip_processing = true;
                    } else {
                        // Create bridge hop field for MAC validation
                        tbl_ingress_interface.apply();
                        // Use second HF
                        meta.egress = hdr.scion_hop_field_1.egIf;
                        meta.ingress = hdr.scion_hop_field_1.inIf;
                        meta.segId = hdr.scion_info_field_0.segId;
                        
                    }
                } else {			
                    // Use first HF
                    meta.egress = hdr.scion_hop_field_0.egIf;
                    meta.ingress = hdr.scion_hop_field_0.inIf;

                    meta.segId = hdr.scion_info_field_0.segId;
                    meta.nextSegId = hdr.scion_info_field_0.segId ^ hdr.scion_hop_field_0.mac[47:32];
                    
                    // Validate MAC
                    if (hdr.scion_common.nextHdr != 0xCB) {
                        // Create bridge hop field for MAC validation
                        create_bridge_hop_1(hdr.scion_info_field_0, hdr.scion_hop_field_0);
                    }
                }
            } else if (hdr.scion_common.pathType == PathType.EMPTY) {
                if (ig_intr_md.ingress_port != PORT_CPU) {
                    // If we receive a packet from another port than CPU we assume that the packet is addressed to this border router
                    send_to_cpu();
                    skip_processing = true;
                }
            } else {
                // Unsupported path type
                drop();
                exit;
            }
                
            bool ingress_verification_successful = tbl_ingress_verification.apply().hit;
            bool bfd_state = true;
            if (local_destination && hdr.scion_common.nextHdr != 0xCB) {
                bfd_state = !tbl_bfd_local.apply().hit;
            // Don't check egress = 0 of non-local dest traffic because it is recirculated and processed during second run!
            } else if (meta.egress != 0 && hdr.scion_common.nextHdr != 0xCB) {
                bfd_state = tbl_bfd_remote.apply().hit;
            }

            // Check whether the MAC was correct and we received the packet on the expect ingress port, or whether verification should be skipped (in case of a one-hop path)
            if ((ingress_verification_successful || ig_intr_md.ingress_port == PORT_CPU) && !skip_processing && bfd_state) {
                // Check whether the packet is intended for the local ISD/AS
                if (local_destination) {
                    if(hdr.scion_common.pathType == PathType.SCION && meta.direction == 0) {
                        // Update the segId in the current info field
                        if (hdr.scion_path_meta.currInf == 0) {
                            hdr.scion_info_field_0.segId = meta.nextSegId;
                        } else if (hdr.scion_path_meta.currInf == 1) {
                            hdr.scion_info_field_1.segId = meta.nextSegId;
                        } else if (hdr.scion_path_meta.currInf == 2) {
                            hdr.scion_info_field_2.segId = meta.nextSegId;
                        }
                    }
                    
                    if (hdr.scion_common.pathType == PathType.EMPTY) {
                        tbl_deliver_local_empty.apply();
                    } else {
                        tbl_deliver_local.apply();
                    }
                } else {
                    switch(tbl_forward.apply().action_run) {
                        forward_local_ipv4:
                        {}
                        default: {
                            if (hdr.scion_path_meta.currInf == 0 || hdr.scion_common.pathType == PathType.ONEHOP) {
                                hdr.scion_info_field_0.segId = meta.nextSegId;
                            } else if (hdr.scion_path_meta.currInf == 1) {
                                hdr.scion_info_field_1.segId = meta.nextSegId;
                            } else if (hdr.scion_path_meta.currInf == 2) {
                                hdr.scion_info_field_2.segId = meta.nextSegId;
                            }
                            
                            // Increase the index to the current hop field and update the header
                            if(hdr.scion_common.pathType == PathType.SCION || hdr.scion_common.pathType == PathType.EPIC) {
                                if (meta.recirculation == 1) {
                                    @in_hash{ meta.currHF = meta.currHF + 1; }
                                }
                                hdr.scion_path_meta.currHF = (bit<6>)meta.currHF;
                            }
                        }
                    }
                }
                
                if(hdr.bridge.hop_field_1.bridge_fields.isValid())
                {
                    tbl_bridge_subkey.apply();
                }
                // Set the source IP/MAC addresses and UDP source port based on the chosen egress port
                // When configuring make sure the destination and source IP type match, otherwise this will overwrite previous selection of IPv4/IPv6
                tbl_set_local_source.apply();
                
                // Exchange egress ports for MAC validation
                if (hdr.scion_common.nextHdr != 0xCB) {
                    update_bridge_ethernet();
                    if (hdr.bridge.main.isValid()) {
                        PortId_t portTemp = ig_tm_md.ucast_egress_port;
                        ig_tm_md.ucast_egress_port = hdr.bridge.main.egressPort;
                        hdr.bridge.main.egressPort = portTemp;
                    }
                }
             } else if(skip_processing) {
                // Packet will be forwarded to CPU
            }
        }

        else if (meta.hvf != 0 && hdr.bridge_after_aes.main.isValid()) {
            if (hdr.bridge_after_aes.main.cryptCounter == 2) {
                if (meta.hvf != hdr.bridge_after_aes.bridge_aes_1.aes1)
                    drop();
            }

            if (hdr.bridge_after_aes.main.cryptCounter == 0) {
                hdr.bridge_after_aes.original_key.key0 = hdr.bridge_after_aes.bridge_aes_1.aes1;
                hdr.bridge_after_aes.original_key.key1 = hdr.bridge_after_aes.bridge_aes_1.aes2;
                hdr.bridge_after_aes.original_key.key2 = hdr.bridge_after_aes.bridge_aes_1.aes3;
                hdr.bridge_after_aes.original_key.key3 = hdr.bridge_after_aes.bridge_aes_1.aes4;
                hdr.bridge_after_aes.key_copy.setValid();
                hdr.bridge_after_aes.key_copy.key0     = hdr.bridge_after_aes.bridge_aes_1.aes1;
                hdr.bridge_after_aes.key_copy.key1     = hdr.bridge_after_aes.bridge_aes_1.aes2;
                hdr.bridge_after_aes.key_copy.key2     = hdr.bridge_after_aes.bridge_aes_1.aes3;
                hdr.bridge_after_aes.key_copy.key3     = hdr.bridge_after_aes.bridge_aes_1.aes4;
            

                hdr.bridge_after_aes.bridge_aes_1.aes1[7:6] = hdr.scion_common.sl;
                hdr.bridge_after_aes.bridge_aes_1.aes2 = hdr.scion_info_field_0.timestamp ;
                hdr.bridge_after_aes.bridge_aes_1.aes3 = hdr.scion_epic.timestamp;
                hdr.bridge_after_aes.bridge_aes_1.aes4 = hdr.scion_epic.counter;
            }
            else if (hdr.bridge_after_aes.main.cryptCounter == 1) {

                hdr.bridge_after_aes.bridge_aes_1.aes1[31:16] = hdr.bridge_after_aes.bridge_aes_1.aes1[31:16]^hdr.scion_addr_common.srcISD;
                hdr.bridge_after_aes.bridge_aes_1.aes1[15:0] = hdr.bridge_after_aes.bridge_aes_1.aes1[15:0]^hdr.scion_addr_common.srcAS[47:32];
                hdr.bridge_after_aes.bridge_aes_1.aes2 = hdr.bridge_after_aes.bridge_aes_1.aes2^hdr.scion_addr_common.srcAS[31:0];
                hdr.bridge_after_aes.bridge_aes_1.aes3 = hdr.bridge_after_aes.bridge_aes_1.aes3^hdr.scion_addr_src_host_32.host;
                hdr.bridge_after_aes.bridge_aes_1.aes4[31:16] = hdr.bridge_after_aes.bridge_aes_1.aes4[31:16]^(meta.payload_len);

                hdr.bridge_after_aes.original_key.key0 = hdr.bridge_after_aes.key_copy.key0;
                hdr.bridge_after_aes.original_key.key1 = hdr.bridge_after_aes.key_copy.key1;
                hdr.bridge_after_aes.original_key.key2 = hdr.bridge_after_aes.key_copy.key2;
                hdr.bridge_after_aes.original_key.key3 = hdr.bridge_after_aes.key_copy.key3;

                hdr.bridge_after_aes.key_copy.setInvalid();
            }
            hdr.bridge_after_aes.main.cryptCounter = meta.cc;
            tbl_select_accelerator.apply();
        }


        if (hdr.bridge_after_aes.main.isValid() && (meta.hvf == 0)) {
            // Set all bridge headers invalid
            hdr.ethernet.setInvalid();
            hdr.bridge.main.setInvalid();
            hdr.bridge_after_aes.main.setInvalid();
            hdr.bridge_after_aes.bridge_aes_1.setInvalid();
            hdr.bridge_after_aes.bridge_aes_2.setInvalid();
            hdr.bridge_after_aes.original_key.setInvalid();
            hdr.bridge_after_aes.key_copy.setInvalid();
            hdr.bridge.hop_field_1.bridge_fields.setInvalid();
            hdr.bridge.hop_field_1.hop_field.setInvalid();
            hdr.bridge.hop_field_2.bridge_fields.setInvalid();
            hdr.bridge.hop_field_2.hop_field.setInvalid();
            hdr.bridge.key.setInvalid();
            meta.skipScion = 1;

            ig_tm_md.ucast_egress_port = hdr.bridge_after_aes.main.egressPort;
        }
        
        hdr.scion_hop_field_0.setInvalid();
        hdr.scion_hop_field_1.setInvalid();

        
    }
}

control ScionEgressControl(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {


    apply {  
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control ScionIngressDeparser(
        packet_out packet,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum() ipv4_checksum;
    Checksum() udp_checksum;

    apply {
#ifndef DISABLE_IPV4
        if(hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});
        } 
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
        if(hdr.ipv6.isValid()) {
            // Update UDP checksum, as this also includes the data we need to take into account the fields we (possibly) changed in the SCION header
            if(hdr.scion_path_meta.isValid()) {
                hdr.udp.checksum = udp_checksum.update(data = {
                                        hdr.ipv6.srcAddr,
                                        hdr.ipv6.dstAddr,
                                        hdr.udp.srcPort,
                                        hdr.udp.dstPort,
                                        hdr.scion_path_meta.currInf, hdr.scion_path_meta.currHF, hdr.scion_path_meta.rsv, hdr.scion_path_meta.seg0Len, hdr.scion_path_meta.seg1Len, hdr.scion_path_meta.seg2Len,
                                        hdr.scion_info_field_0.segId,
                                        hdr.scion_info_field_1.segId,
                                        hdr.scion_info_field_2.segId,
                                        ig_md.udp_checksum_tmp
                                    }, zeros_as_ones = true);
             } else {
                // Assume it is a one-hop path
                hdr.udp.checksum = udp_checksum.update(data = {
                                        hdr.ipv6.srcAddr,
                                        hdr.ipv6.dstAddr,
                                        hdr.udp.srcPort,
                                        hdr.udp.dstPort,
                                        hdr.scion_info_field_0.segId,
                                        ig_md.udp_checksum_tmp
                                    }, zeros_as_ones = true);
            }
        }
#endif /* DISABLE_IPV6 */

        packet.emit<header_t>(hdr);
    }
}

control ScionEgressDeparser(
        packet_out packet,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(ScionIngressParser(),
         ScionIngressControl(),
         ScionIngressDeparser(),
         ScionEgressParser(),
         ScionEgressControl(),
         ScionEgressDeparser()) scion_pipe;

Switch(scion_pipe) main;
