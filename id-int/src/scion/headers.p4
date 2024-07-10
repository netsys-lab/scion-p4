#ifndef SCION_HEADERS_P4_GUARD
#define SCION_HEADERS_P4_GUARD

/////////////////////////
// Types and Constants //
/////////////////////////

typedef bit<16> sc_isd_t;
typedef bit<48> sc_asn_t;

enum bit<8> sc_proto_t {
    TCP            = 6,
    UDP            = 17,
    HOP_BY_HOP_EXT = 200,
    END_TO_END_EXT = 201,
    SCMP           = 202,
    BFD            = 203,
    ID_INT         = 253, // unofficial experimental use
    EXPERIMENT2    = 254
}

enum bit<8> sc_path_type_t {
    EMPTY   = 0,
    SCION   = 1,
    ONE_HOP = 2,
    EPIC    = 3,
    COLIBRI = 4
}

///////////
// SCION //
///////////

const int SC_MAC_HDR_LEN = 1020;  // 255 * 4 bytes
const int SC_COMMON_HDR_LEN = 12; // 3 * 4 bytes

header sc_common_h {
    // Common SCION header
    bit<4>         version;       // header version (= 0)
    bit<8>         qos;           // traffic class
    bit<20>        flow_id;       // mandatory flow id
    bit<8>         next_hdr;      // next header type
    bit<8>         hdr_len;       // header length in units of 4 bytes
    bit<16>        payload_len;   // payload length in bytes
    sc_path_type_t path_type;     // path type
    bit<8>         host_type_len; // DT, DL, ST, SL
    bit<16>        rsv;           // reserved

    // Common address header
    sc_isd_t dst_isd;
    sc_asn_t dst_asn;
    sc_isd_t src_isd;
    sc_asn_t src_asn;
}

// 4 byte host address
header sc_host_addr_4_h {
    bit<32> addr;
}

// 16 byte host address
header sc_host_addr_16_h {
    bit<128> addr;
}

/////////////////////////
// Standard SCION Path //
/////////////////////////

const int SC_PATH_META_LEN = 4;  // 1 * 4 byte
const int SC_INFO_FIELD_LEN = 8; // 2 * 4 byte
const int SC_HOP_FIELD_LEN = 12; // 3 * 4 byte

// SCION Path meta header
header sc_path_meta_h {
    bit<2> curr_inf; // index of the current info field
    bit<6> curr_hf;  // index of the current hop field
    bit<6> rsv;      // reserved
    bit<6> seg0_len; // number of hop fields in path segment 0
    bit<6> seg1_len; // number of hop fields in path segment 1
    bit<6> seg2_len; // number of hop fields in path segment 2
}

// Info field
header sc_info_h {
    bit<6>  rsv1;    // reserved
    bit<1>  peering; // peering hop
    bit<1>  cons;    // path in construction direction (1) or against construction direction (0)
    bit<8>  rsv2;    // reserved
    bit<16> seg_id;  // segment ID for MAC chaining
    bit<32> tstamp;  // timestamp
}

// Hop field
header sc_hop_h {
    bit<6>  rsv;      // reserved
    bit<1>  ig_alert; // ingress router alert
    bit<1>  eg_alert; // egress router alert
    bit<8>  exp_time; // expiration time
    bit<16> ig_if;    // AS ingress IFID
    bit<16> eg_if;    // AS egress IFID
    bit<48> mac;      // message authentication code
}

//////////////////////////
// Hop-by-Hop Extension //
//////////////////////////

header sc_hbh_ext_h {
    sc_proto_t next_hdr; // next header type
    bit<8> ext_len;      // total extension heder length in multiples of 4 bytes
}

//////////////////////////////
// Validation Bridge Header //
//////////////////////////////

// First four bytes of the bridge header
header sc_bridge_meta_h {
    bit<1>  check_first_hf;  // first HF present, check its MAC
    bit<1>  check_second_hf; // second HF present, check its MAC
    bit<1>  idint;           // set if an ID-INT bridge header follows
    bit<1>  rsv0;            // reserved
    bit<1>  first_hf_valid;  // first HF is valid
    bit<1>  second_hf_valid; // second HF is valid
    bit<2>  rsv1;            // reserved
    bit<8>  length;          // length of the bridge header in bytes
    bit<16> egress_port;     // final egress port
}

// // Additional header fields needed for the MAC computation
// header sc_mac_input_h {
//     bit<16> zero;   // part of the info field that is zeroed out
//     bit<16> beta_i; // for MAC chaining
//     bit<32> tstamp; // timestamp
// }

///////////////////
// Parser Output //
///////////////////

const int SC_MAX_INFO_CNT = 3;
const int SC_MAX_HF_CNT   = 8;

struct sc_headers_t {
    sc_common_h                common;
    sc_host_addr_4_h           dst_host_4;
    sc_host_addr_16_h          dst_host_16;
    sc_host_addr_4_h           src_host_4;
    sc_host_addr_16_h          src_host_16;
    sc_path_meta_h             path_meta;
    sc_info_h[SC_MAX_INFO_CNT] info;
    sc_hop_h[SC_MAX_HF_CNT]    hop;
}

struct sc_bridge_t {
    sc_bridge_meta_h meta;
    sc_info_h        info0;
    sc_hop_h         hf0;
    sc_info_h        info1;
    sc_hop_h         hf1;
}

struct sc_meta_t {
    bit<1> as_ingress; // whether the current hop is the first in a new AS
    bit<1> as_egress;  // whether the current hop is an egress border router
    bit<6> curr_hf;    // current hop
}

#endif // SCION_HEADERS_P4_GUARD
