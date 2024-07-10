#ifndef IDINT_HEADERS_P4_GUARD
#define IDINT_HEADERS_P4_GUARD

#include "../internal_headers.p4"


///////////
// Types //
///////////

enum bit<2> idint_mode_t {
    UNLIMITED = 0,
    ONE_NODE = 1,
    TWO_NODES = 2,
    THRESS_NODES = 3
}

enum bit<2> idint_verif_t {
    THIRD_PARTY = 0,
    DESTINATION = 1,
    SOURCE = 2
}

enum bit<3> idint_af_t {
    FIRST = 0,
    LAST  = 1,
    MIN   = 2,
    MAX   = 3,
    SUM   = 4
}

////////////////////////
// ID-INT on the Wire //
////////////////////////

#define IDINT_INST_FIELDS \
    bit<1>     node_count; \
    bit<1>     node_id; \
    bit<1>     ingress_iface; \
    bit<1>     egress_iface; \
    idint_af_t aggr_func_1; \
    idint_af_t aggr_func_2; \
    idint_af_t aggr_func_3; \
    idint_af_t aggr_func_4; \
    bit<8>     inst1; \
    bit<8>     inst2; \
    bit<8>     inst3; \
    bit<8>     inst4

// ID-INT main header
header idint_h {
    // Flags and hop counters
    bit<3> ver;                // header version (= 0)
    bit<1> infrastructure;     //
    bit<1> discard;            //
    bit<1> encrypt;            // request encryption
    bit<1> hop_count_exceeded; //
    bit<1> mtu_exceeded;       // was 'stack_full'
    bit<8> mode_and_verif;     // Mode, Verifier, VT, VL
    bit<8> length;             // was 'tos'
    bit<8> next_hdr;           // was 'free_len'
    bit<6> delay_hops;         //
    bit<2> rsv0;               // reserved
    bit<6> rem_hops;           //
    bit<2> rsv1;               // reserved

    // Instructions
    IDINT_INST_FIELDS;

    // Timestamp
    bit<48> src_ts;
    bit<16> src_port;
}

header idint_verif_h {
    bit<16> isd;
    bit<48> asn;
}

header scion_host_4_h {
    bit<32> addr;
}

header scion_host_8_h {
    bit<64> addr;
}

header scion_host_12_h {
    bit<96> addr;
}

header scion_host_16_h {
    bit<128> addr;
}

struct idint_verif_host_t {
    scion_host_4_h host4;
    scion_host_16_h host16;
}

#define IDINT_MD_HDR_FIELDS \
    bit<1>  source; \
    bit<1>  ingress; \
    bit<1>  egress; \
    bit<1>  aggregate; \
    bit<1>  encrypted; \
    bit<3>  reserved_flags; \
    bit<6>  hop; \
    bit<2>  reserved; \
    bit<16> flags_and_meta_len

// ID-INT metadata header
header idint_metadata_header_h {
    IDINT_MD_HDR_FIELDS;
}

header idint_nonce_h {
    bit<96> nonce;
}

header idint_meta_2_h {
    bit<16> data;
}

header idint_meta_4_h {
    bit<32> data;
}

header idint_meta_6_h {
    bit<48> data;
}

header idint_meta_8_h {
    bit<64> data;
}

struct idint_meta_t {
    idint_meta_2_h meta2;
    idint_meta_4_h meta4;
    idint_meta_6_h meta6;
    idint_meta_8_h meta8;
}

#define IDINT_MAC_HDR_FIELDS bit<32> mac

header idint_mac_h {
    IDINT_MAC_HDR_FIELDS;
}

struct idint_telemetry_t {
    idint_meta_4_h node_count;
    idint_meta_4_h node_id;
    idint_meta_4_h ingress_iface;
    idint_meta_4_h egress_iface;
    idint_meta_t   data1;
    idint_meta_t   data2;
    idint_meta_t   data3;
    idint_meta_t   data4;
}

/////////////
// Ingress //
/////////////

struct idint_ig_headers_t {
    // Main header with instructions and timestamp
    idint_h hdr;

    // Optional verifier address
    idint_verif_h verif;
    idint_verif_host_t verif_host;

    // Last-hop telemetry stack entry
    idint_metadata_header_h md_hdr;
    idint_telemetry_t metadata;
    idint_mac_h mac;
}

// Key for MAC and encryption
header idint_key_h {
    bit<32> key_id;
}

header idint_bridge_ig_h {
    INTERNAL_HDR_FIELDS;
    bit<1>   merge;
    bit<15>  ingress_port;
    bit<48>  ingress_tstamp;
    IDINT_INST_FIELDS;
    IDINT_MD_HDR_FIELDS;
    IDINT_MAC_HDR_FIELDS;
}

// Header emitted by ingress deparser. Is parsed into idint_bridge_eg_t in the egress parser
struct idint_bridge_if_t {
    idint_bridge_ig_h hdr;
    idint_key_h       key;
    idint_meta_4_h    node_count;
    idint_meta_4_h    node_id;
    idint_meta_4_h    ingress_iface;
    idint_meta_4_h    egress_iface;
    idint_meta_8_h    data1;
    idint_meta_8_h    data2;
    idint_meta_8_h    data3;
    idint_meta_8_h    data4;
}

////////////
// Egress //
////////////

// Egress internal metadata
header idint_eg_metadata_t {
    @flexible
    MirrorId_t mirror_session;
}

// Metadata from ingress pipeline
header idint_bridge_meta_ig_h {
    INTERNAL_HDR_FIELDS;
    bit<1>  merge;
    bit<15> ingress_port;
    bit<48> ingress_tstamp;
    IDINT_INST_FIELDS;
}

// Metadata for external crypto accelerator
header idint_bridge_meta_eg_h {
    bit     mac;        // MAC the telemetry with the given key
    bit     encrypt;    // encrypt the telemetry with the given key, implies presence of a nonce
    @padding
    bit<6>  pad0;       // padding (arbitrary value)
    bit<8>  hop_offset; // position of the final hop entry in the packet as a byte offset
    bit<8>  hop_len;    // length of the hop entry on the telemetry stack
    @padding
    bit<8> pad1;        // padding (arbitrary value)
}

struct idint_bridge_eg_t {
    idint_bridge_meta_ig_h  ig_meta;
    idint_bridge_meta_eg_h  eg_meta;
    idint_key_h             key_hdr;
    idint_metadata_header_h md_hdr;
    idint_telemetry_t       metadata;
    idint_mac_h             mac;
}

///////////////////
// Egress Mirror //
///////////////////

header eg_mirror_h {
    INTERNAL_HDR_FIELDS;
    // TODO: Add actual telemetry metadata
}

#endif // IDINT_HEADERS_P4_GUARD
