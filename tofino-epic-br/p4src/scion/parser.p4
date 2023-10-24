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

#ifndef _scion_parser_p4__
#define _scion_parser_p4__

#include <core.p4>
#include <tna.p4>

#include "headers.p4"


/*************************************************************************
************************** P A R S E R  **********************************
*************************************************************************/

// Extract SCION header stack
parser ScionParser(
    packet_in   packet,
    out scion_t scion,
    Checksum  udp_checksum,
    out bit<6>  currHF,
    out bit<8>  nextHdr
)
{
    ParserCounter() hf_counter;
    
    state start {
		packet.extract(scion.common);
		packet.extract(scion.addr_common);
		
		nextHdr = scion.common.nextHdr;
		
		hf_counter.set(scion.common.hdrLen, MAX_SCION_HDR_LEN / 4, 0, 0, 0);
		hf_counter.decrement(SCION_COMMON_HDR_LEN / 4);
		hf_counter.decrement(SCION_ADDR_COMMON_HDR_LEN / 4);

		currHF = 0;

		transition select(scion.common.dl, scion.common.sl) {
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
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_src_host_32);
		
		hf_counter.decrement(2);

		transition path;
	}

	state addr_dst_src_host_32_64 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		
		hf_counter.decrement(3);

		transition path;
	}

	state addr_dst_src_host_32_96 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		packet.extract(scion.addr_src_host_32_3);
		
		hf_counter.decrement(4);

		transition path;
	}

	state addr_dst_src_host_32_128 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_src_host_128);
		
		hf_counter.decrement(5);

		transition path;
	}

	state addr_dst_src_host_64_32 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_src_host_32);
		
		hf_counter.decrement(3);

		transition path;
	}

	state addr_dst_src_host_64_64 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		
		hf_counter.decrement(4);

		transition path;
	}

	state addr_dst_src_host_64_96 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		packet.extract(scion.addr_src_host_32_3);
		
		hf_counter.decrement(5);

		transition path;
	}

	state addr_dst_src_host_64_128 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_src_host_128);
		
		hf_counter.decrement(6);

		transition path;
	}

	state addr_dst_src_host_96_32 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_dst_host_32_3);
		packet.extract(scion.addr_src_host_32);
		
		hf_counter.decrement(4);

		transition path;
	}

	state addr_dst_src_host_96_64 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_dst_host_32_3);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		
		hf_counter.decrement(5);

		transition path;
	}

	state addr_dst_src_host_96_96 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_dst_host_32_3);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		packet.extract(scion.addr_src_host_32_3);
		
		hf_counter.decrement(6);
	
		transition path;
	}

	state addr_dst_src_host_96_128 {
		packet.extract(scion.addr_dst_host_32);
		packet.extract(scion.addr_dst_host_32_2);
		packet.extract(scion.addr_dst_host_32_3);
		packet.extract(scion.addr_src_host_128);
		
		hf_counter.decrement(7);

		transition path;
	}

	state addr_dst_src_host_128_32 {
		packet.extract(scion.addr_dst_host_128);
		packet.extract(scion.addr_src_host_32);
		
		hf_counter.decrement(5);

		transition path;
	}

	state addr_dst_src_host_128_64 {
		packet.extract(scion.addr_dst_host_128);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		
		hf_counter.decrement(6);

		transition path;
	}

	state addr_dst_src_host_128_96 {
		packet.extract(scion.addr_dst_host_128);
		packet.extract(scion.addr_src_host_32);
		packet.extract(scion.addr_src_host_32_2);
		packet.extract(scion.addr_src_host_32_3);
		
		hf_counter.decrement(7);

		transition path;
	}

	state addr_dst_src_host_128_128 {
		packet.extract(scion.addr_dst_host_128);
		packet.extract(scion.addr_src_host_128);
		
		hf_counter.decrement(8);
		
		transition path;
	}

	state path {
		transition select(scion.common.pathType) {
		    PathType.EMPTY: accept;
			PathType.SCION: path_scion;
			PathType.ONEHOP: path_onehop;
			// Other path types are not supported
		}
	}
	
	state path_onehop {
	    packet.extract(scion.info_field_0);
	    
	    hf_counter.decrement(SCION_INFO_LEN / 4);
	    
	    transition extract_current_hop_field_0;
	}

	state path_scion {
		packet.extract(scion.path_meta);
		udp_checksum.subtract({scion.path_meta.currInf, scion.path_meta.currHF, scion.path_meta.rsv, scion.path_meta.seg0Len, scion.path_meta.seg1Len, scion.path_meta.seg2Len});
		
		hf_counter.decrement(SCION_PATH_META_LEN / 4);
		currHF = scion.path_meta.currHF;

		// We assume there is at least one info field present
		transition select(scion.path_meta.seg1Len, scion.path_meta.seg2Len) {
			(0, 0): info_field_0;
			(_, 0): info_field_1;
			default: info_field_2;
		}		
	}

	state info_field_0 {
		packet.extract(scion.info_field_0);
		udp_checksum.subtract({scion.info_field_0.segId});
		
		hf_counter.decrement(SCION_INFO_LEN / 4);

		scion.info_field_1.segId = 0;
		scion.info_field_2.segId = 0;

		transition select_current_hop_field;
	}

	state info_field_1 {
		packet.extract(scion.info_field_0);
		udp_checksum.subtract({scion.info_field_0.segId});
		packet.extract(scion.info_field_1);
		udp_checksum.subtract({scion.info_field_1.segId});
		
		hf_counter.decrement(2 * SCION_INFO_LEN / 4);

		scion.info_field_2.segId = 0;

		transition select_current_hop_field;
	}

	state info_field_2 {
		packet.extract(scion.info_field_0);
		udp_checksum.subtract({scion.info_field_0.segId});
		packet.extract(scion.info_field_1);
		udp_checksum.subtract({scion.info_field_1.segId});
		packet.extract(scion.info_field_2);
		udp_checksum.subtract({scion.info_field_2.segId});
		
		hf_counter.decrement(3 * SCION_INFO_LEN / 4);

		transition select_current_hop_field;
	}
	
	state select_current_hop_field {
	    transition select(currHF) {
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
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(2 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_1 {
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(3 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_2 {
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(4 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_3 {
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(5 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_4 {
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(6 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_5 {
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(7 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_6 {
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(8 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_current_hop_field_7 {
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    packet.extract(scion.hop_fields.next);
	    
	    scion.hop_field_0 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(9 * SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_next_hop_field;
	        default: check_for_extension;
	    }
	}
	
	state extract_next_hop_field {
	    scion.hop_field_1 = packet.lookahead<scion_hop_field_t>();
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_other_hop_fields;
	        default: check_for_extension;
	    }
	}
	
	state extract_other_hop_fields {
	    packet.extract(scion.hop_fields.next);
	    
	    hf_counter.decrement(SCION_HOP_LEN / 4);
	    
	    transition select(hf_counter.is_negative()) {
	        false: extract_other_hop_fields;
	        default: check_for_extension;
	    }
	}
	
	state check_for_extension {
	    transition select(nextHdr) {
	        200: scion_hop_by_hop;
	        default: accept;
        }
	}
	
	state scion_hop_by_hop {
	    packet.extract(scion.hop_by_hop);
	    
	    transition accept;
    }
}

#endif //_scion_parser_p4__
