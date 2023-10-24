// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _bridge_parser_p4__
#define _bridge_parser_p4__

#include <core.p4>
#include <tna.p4>

#include "headers.p4"

// Extract bridge header used for MAC calculation on external device
parser BridgeParser(
    packet_in           packet,
    out bridge_t        bridge
)
{
    // Extract the main bridge header
	state start {
	    packet.extract(bridge.main);
	    
	    // Check, if the first hop field is present
	    transition select(bridge.main.checkFirstHf) {
	        1: bridge_first_hf;
	        default: accept;
        }
    }
    
    // Extract first hop field
    state bridge_first_hf {
        packet.extract(bridge.hop_field_1.bridge_fields);
        packet.extract(bridge.hop_field_1.hop_field);
        
        // Check, if second hop field is present (only, if first hop field was present)
        transition select(bridge.main.checkSecHf) {
            1: bridge_sec_hf;
            default: accept;
        }
    }
    
    // Extract second hop field
    state bridge_sec_hf {
        packet.extract(bridge.hop_field_2.bridge_fields);
        packet.extract(bridge.hop_field_2.hop_field);
        
        transition accept;
    }
}

#endif //_bridge_parser_p4__
