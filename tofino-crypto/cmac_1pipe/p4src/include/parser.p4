// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef INCLUDE_PARSER_P4_GUARD
#define INCLUDE_PARSER_P4_GUARD

/////////////////////////
// Constants and Types //
/////////////////////////

type bit<48> mac_addr_t;

enum bit<16> ether_type_t {
    IPV4   = 0x0800,
    IPV6   = 0x86DD,
    BRIDGE = 0x9999
}

/////////////
// Headers //
/////////////

header ethernet_h {
    mac_addr_t   dst;
    mac_addr_t   src;
    ether_type_t etype;
}

// First four bytes of the bridge header
header bridge_meta_h {
    bit<1> check_mac0;
    bit<1> check_mac1;
    bit<1> iter;        // first or second pass through AES pipeline
    bit<5> reserved;
    bit<8> length;      // length of the bridge header in bytes
    bit<5> user_data0;
    bit<9> egress_port; // final egress port if the packet is accepted
    bit<2> user_data1;
}

header cmac_block_h {
    bit<32> c0;
    bit<32> c1;
    bit<32> c2;
    bit<32> c3;
    bit<48> cmac; // MAC to compare against
}

struct cmac_headers_t {
    ethernet_h    ethernet;
    bridge_meta_h meta;
    cmac_block_h  block0;
    cmac_block_h  block1;
}

//////////////
// Metadata //
//////////////

struct cmac_metadata_t {
}

////////////
// Parser //
////////////

parser CmacParser(packet_in pkt,
    out cmac_headers_t      hdr,
    out cmac_metadata_t     meta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etype) {
            ether_type_t.BRIDGE : bridge;
            default             : accept;
        }
    }

    state bridge {
        pkt.extract(hdr.meta);
        transition select(hdr.meta.check_mac0) {
            1       : block0;
            default : accept;
        }
    }

    state block0 {
        pkt.extract(hdr.block0);
        transition select(hdr.meta.check_mac1) {
            1       : block1;
            default : accept;
        }
    }

    state block1 {
        pkt.extract(hdr.block1);
        transition accept;
    }
}

#endif // INCLUDE_PARSER_P4_GUARD
