#ifndef COMMON_HEADERS_P4_GUARD
#define COMMON_HEADERS_P4_GUARD

/////////////////////////
// Constants and Types //
/////////////////////////

type bit<48> mac_addr_t;

enum bit<16> ether_type_t {
    IPV4   = 0x0800,
    IPV6   = 0x86DD,
    BRIDGE = 0x1234
}

enum bit<8> ip_proto_t {
    UDP = 0x11
}

/////////////
// Headers //
/////////////

header ethernet_h {
    mac_addr_t   dst;
    mac_addr_t   src;
    ether_type_t etype;
}

header ipv4_h {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     diffserv;
    bit<16>    total_len;
    bit<16>    id;
    bit<3>     flags;
    bit<13>    frag_offset;
    bit<8>     ttl;
    ip_proto_t protocol;
    bit<16>    chksum;
    bit<32>    src;
    bit<32>    dst;
}

header ipv6_h {
    bit<4>     version;
    bit<8>     traffic_class;
    bit<20>    flow_label;
    bit<16>    payload_len;
    ip_proto_t next_hdr;
    bit<8>     hop_limit;
    bit<128>   src;
    bit<128>   dst;
}

header udp_h {
    bit<16> src;
    bit<16> dst;
    bit<16> length;
    bit<16> chksum;
}

#endif // COMMON_HEADERS_P4_GUARD
