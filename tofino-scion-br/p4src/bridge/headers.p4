// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef __BRIDGE_P4__
#define __BRIDGE_P4__

#include "../scion/headers.p4"

header bridge_main_t {
    bit<1> checkFirstHf;
    bit<1> checkSecHf;
    bit<2> rsv1;
    bit<1> okFirstHf;
    bit<1> okSecHf;
    bit<2> rsv2;
    bit<8> len;
    bit<5> varLen;
    bit<9> egressPort;
    bit<2> switchData;
}

header bridge_info_t {
    bit<16> rsv;
    bit<16> beta;
    bit<32> timestamp;
}

header bridge_hop_field_t {
    bit<8>    routerAlerts;
    bit<8>    expTime;
    bit<16>   inIf;
    bit<16>   egIf;
    bit<16>   reserved;
    bit<48>   mac;
}

struct bridge_hf_t {
    bridge_info_t     bridge_fields;
    bridge_hop_field_t hop_field;
}

// The final bridge header
struct bridge_t {
	bridge_main_t   main;
	bridge_hf_t     hop_field_1;
	bridge_hf_t     hop_field_2;
}

#endif //__BRIDGE_P4__
