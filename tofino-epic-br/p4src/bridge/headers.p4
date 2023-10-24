// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef __BRIDGE_P4__
#define __BRIDGE_P4__

#include "../scion/headers.p4"

header bridge_main_t {
    bit<1> checkFirstHf;
    bit<1> checkSecHf;
    bit<2> cryptCounter;
    bit<4> rsv;
    bit<8> len;
    bit<5> varLen;
    bit<9> egressPort;
    bit<2> switchData;
}

header bridge_aes_t {
    bit<32> aes1;
    bit<32> aes2;
    bit<32> aes3;
    bit<32> aes4;
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
}

struct bridge_hf_t {
    bridge_info_t     bridge_fields;
    bridge_hop_field_t hop_field;
}

header bridge_prev_mac_t {
    bit<32> mac;
}

header bridge_key_t {
    bit<32> key0;
    bit<32> key1;
    bit<32> key2;
    bit<32> key3;
    
}

// The final bridge header
struct bridge_t {
	bridge_main_t   main;
	bridge_hf_t     hop_field_1;
	bridge_hf_t     hop_field_2;
    bridge_key_t    key;
}

struct bridge_after_aes_t {
    bridge_main_t  main;
    bridge_aes_t   bridge_aes_1;
    bridge_aes_t   bridge_aes_2;
    bridge_key_t   original_key;
    bridge_key_t   key_copy;
}

#endif //__BRIDGE_P4__
