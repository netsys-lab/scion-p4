// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _bridge_parser_p4__
#define _bridge_parser_p4__

#include <core.p4>
#include <tna.p4>

#include "headers.p4"

// Extract bridge header used for MAC calculation on external device
parser BridgeParser(
    packet_in           packet,
    out bridge_after_aes_t        bridge_after_aes
)
{
    // Extract the main bridge header
	state start {
	    packet.extract(bridge_after_aes.main);
	    
	    // Check, if the first hop field is present
	    transition select(bridge_after_aes.main.checkFirstHf) {
	        1: bridge_first_hf;
	        default: accept;
        }
    }
    
    // Extract first hop field
    state bridge_first_hf {
        packet.extract(bridge_after_aes.bridge_aes_1);
        
        // Check, if second hop field is present (only, if first hop field was present)
        transition select(bridge_after_aes.main.checkSecHf) {
            1: bridge_sec_hf;
            default: key_extract;
        }
    }

    
    // Extract second hop field
    state bridge_sec_hf {
        packet.extract(bridge_after_aes.bridge_aes_2);
        
        transition key_extract;

    }
    state key_extract {
        packet.extract(bridge_after_aes.original_key);
        transition select(bridge_after_aes.main.cryptCounter) {
            1: sec_key;
            default: accept;
        }
    }
    
    state sec_key {
        packet.extract(bridge_after_aes.key_copy);
        transition accept;
    }
     
    
}

#endif //_bridge_parser_p4__
