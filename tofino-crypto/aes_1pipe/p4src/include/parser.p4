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
    bit<1>  enable_block0; // encrypt block 0
    bit<1>  enable_block1; // encrypt block 1
    bit<1>  iter;          // first or second pass through AES pipeline
    bit<5>  reserved;
    bit<8>  length;        // length of the bridge header in bytes
    bit<16> user_data;
}

header aes_block_h {
    bit<32> c0;
    bit<32> c1;
    bit<32> c2;
    bit<32> c3;
}

struct aes_headers_t {
    ethernet_h    ethernet;
    bridge_meta_h meta;
    aes_block_h   block0;
    aes_block_h   block1;
    aes_block_h   key;
}

//////////////
// Metadata //
//////////////

struct aes_metadata_t {
    // Copy of the key for a second parallel key expansion in another register
    // group
    aes_block_h key;
}

////////////
// Parser //
////////////

parser AesParser(packet_in pkt,
    out aes_headers_t      hdr,
    out aes_metadata_t     meta)
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
        transition select(hdr.meta.enable_block0) {
            1       : block0;
            default : key;
        }
    }

    state block0 {
        pkt.extract(hdr.block0);
        transition select(hdr.meta.enable_block1) {
            1       : block1;
            default : key;
        }
    }

    state block1 {
        pkt.extract(hdr.block1);
        transition key;
    }

    state key {
        meta.key = pkt.lookahead<aes_block_h>();
        pkt.extract(hdr.key);
        transition accept;
    }
}

#endif // INCLUDE_PARSER_P4_GUARD
