// SPDX-License-Identifier: AGPL-3.0-or-later
#include <core.p4>
#include <t2na.p4>

// #define SINK_IN_EGRESS

/////////////////////////
// Constants and Types //
/////////////////////////

typedef bit<32> latency_t;
typedef bit<32> index_t;

type bit<48> mac_addr_t;

enum bit<16> ether_type_t {
    IPV4   = 0x0800,
    ARP    = 0x0806,
    IPV6   = 0x86DD
}

enum bit<8> ip_proto_t {
    ICMP     = 1,
    TCP      = 6,
    UDP      = 17,
    IPv6Frag = 44,
    ICMPv6   = 58
}

enum bit<8> icmp6_type {
    DestUnreach   = 1,
    PacketTooBig  = 2,
    TimeExceeded  = 3,
    ParamProblem  = 4,
    EchoRequest   = 128,
    EchoReply     = 129,
    RouterSolicit = 133,
    RouterAdvert  = 134,
    NeighSolicit  = 135,
    NeighAdvert   = 136,
    Redirect      = 137
}

/////////////
// Headers //
/////////////

header ethernet_h {
    mac_addr_t   dst;
    mac_addr_t   src;
    ether_type_t etype;
}

header arp_h {
    bit<16>    hw_type;
    bit<16>    proto;
    bit<8>     hw_len;
    bit<8>     proto_len;
    bit<16>    operation;
    mac_addr_t sender_hw_addr;
    bit<32>    sender_proto_addr;
    mac_addr_t target_hw_addr;
    bit<32>    target_proto_addr;
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

header icmp6_h {
    icmp6_type type;
    bit<8>     code;
    bit<16>    chksum;
    bit<1>     router;
    bit<1>     solicited;
    bit<1>     override;
    bit<29>    reserved;
    bit<128>   target;
    // source/target link-layer address option
    bit<8>     opt_type;
    bit<8>     opt_length;
    mac_addr_t target_ll;
}

header udp_h {
    bit<16> src;
    bit<16> dst;
    bit<16> length;
    bit<16> chksum;
}

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
    IDINT          = 253, // EXPERIMENT1
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

const int SC_MAX_HDR_LEN = 1020;  // 255 * 4 bytes
const int SC_COMMON_HDR_LEN = 28; // 7 * 4 bytes

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

///////////////
// EPIC Path //
///////////////

const int SC_EPIC_LEN = 16; // 4 * 4 byte

header sc_epic_h {
    bit<32> timestamp;
    bit<32> counter;
    bit<32> phvf;
    bit<32> lhvf;
}

////////////
// ID-INT //
////////////

// ID-INT main header
header idint_h {
    bit<8> ver_flags;
    bit<8> mode_verifier;
    bit<8> length;
    bit<8> next_hdr;
    bit<64> instructions;
    bit<64> timestamp;
    // no verifier address (assert Vrf != 0)
}

header idint_stack_h {
    varbit<(32*32)> stack;
}

/////////////////
// ScionParser //
/////////////////

const int SC_MAX_INFO_CNT = 3;
const int SC_MAX_HF_CNT   = 8;

struct sc_headers_t {
    sc_common_h                common;
    sc_host_addr_4_h           dst_host_4;
    sc_host_addr_16_h          dst_host_16;
    sc_host_addr_4_h           src_host_4;
    sc_host_addr_16_h          src_host_16;
    sc_epic_h                  epic;
    sc_path_meta_h             path_meta;
    sc_info_h[SC_MAX_INFO_CNT] info;
    sc_hop_h[SC_MAX_HF_CNT]    hop;
}

// Parser for the SCION header without extensions
parser ScionParser(packet_in pkt,
    out sc_headers_t         hdr,
    Checksum                 udp_chksum)
{
    // The parser counter is used to keep track of the remaining SCION header length.
    // By subtracting all header we have parsed, it can tell us the the number of hop fields in
    // the path.
    ParserCounter() counter;

    ////////////////////
    // Common Headers //
    ////////////////////

    state start {
        pkt.extract(hdr.common);
        udp_chksum.subtract(hdr.common.version);
        udp_chksum.subtract(hdr.common.qos);
        udp_chksum.subtract(hdr.common.flow_id);
        counter.set(hdr.common.hdr_len);
        counter.decrement(SC_COMMON_HDR_LEN / 4);
        transition host_address;
    }

    ////////////////////
    // Host Addresses //
    ////////////////////

    state host_address {
        transition select (hdr.common.host_type_len) {
            0x00 &&& 0xf0: dst_host_4;
            0x30 &&& 0xf0: dst_host_16;
        }
    }

    state dst_host_4 {
        pkt.extract(hdr.dst_host_4);
        counter.decrement(1);
        transition src_host;
    }

    state dst_host_16 {
        pkt.extract(hdr.dst_host_16);
        counter.decrement(4);
        transition src_host;
    }

    state src_host {
        transition select (hdr.common.host_type_len) {
            0x00 &&& 0x0f: src_host_4;
            0x03 &&& 0x0f: src_host_16;
        }
    }

    state src_host_4 {
        pkt.extract(hdr.src_host_4);
        counter.decrement(1);
        transition path;
    }

    state src_host_16 {
        pkt.extract(hdr.src_host_16);
        counter.decrement(4);
        transition path;
    }

    /////////////////////////
    // Standard SCION Path //
    /////////////////////////

    state path {
        transition select (hdr.common.path_type) {
            sc_path_type_t.SCION: scion_path;
            sc_path_type_t.EPIC : epic_path;
        }
    }

    state epic_path {
        pkt.extract(hdr.epic);
        counter.decrement(SC_EPIC_LEN / 4);
        transition scion_path;
    }

    state scion_path {
        pkt.extract(hdr.path_meta);
        counter.decrement(SC_PATH_META_LEN / 4);
        transition select (hdr.path_meta.seg1_len, hdr.path_meta.seg2_len) {
            (0, 0) : info_field_1;
            (_, 0) : info_field_2;
            default: info_field_3;
        }
    }

    @critical
    state info_field_1 {
        pkt.extract(hdr.info[0]);
        counter.decrement(SC_INFO_FIELD_LEN / 4);
        transition hop_fields;
    }

    @critical
    state info_field_2 {
        pkt.extract(hdr.info[0]);
        pkt.extract(hdr.info[1]);
        counter.decrement(2 * SC_INFO_FIELD_LEN / 4);
        transition hop_fields;
    }

    @critical
    state info_field_3 {
        pkt.extract(hdr.info[0]);
        pkt.extract(hdr.info[1]);
        pkt.extract(hdr.info[2]);
        counter.decrement(3 * SC_INFO_FIELD_LEN / 4);
        transition hop_fields;
    }

    // Extract the hop fields
    state hop_fields {
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_zero()) {
            false: hop_fields;
            true : accept;
        }
    }
}

/////////////////
// Packet Sink //
/////////////////

control Sink(
    in bit<64>   rx_timestamp,
    in latency_t ts_delta)
{
    // === Timestamps ===
    // Store the timestamps of the first and the last received packet.

    Register<bit<64>, bit<8>>(1) reg_rx_first;
    Register<bit<64>, bit<8>>(1) reg_rx_last;

    Register<bit<1>, bit<8>>(1) reg_rx_first_pkt;
    RegisterAction<bit<1>, bit<8>, bit<1>>(reg_rx_first_pkt) is_first_pkt = {
        void apply(inout bit<1> value, out bit<1> result) {
            result = value;
            value = 0;
        }
    };

    // === Latency array ===
    // Registers storing an array of latency values. The array is overwritten
    // when it gets full.

    const int LAT_ARRAY_COUNT = 16;
    const int LAT_ARRAY_SIZE = 94208;

    // The packet latency array is split over multiple registers.
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array0;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array1;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array2;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array3;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array4;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array5;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array6;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array7;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array8;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array9;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array10;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array11;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array12;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array13;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array14;
    Register<latency_t, index_t>(LAT_ARRAY_SIZE) reg_lat_array15;

    // Index of the current register
    Register<index_t, bit<8>>(1) reg_array_index;
    RegisterAction<index_t, bit<8>, index_t>(reg_array_index) inc_array_index = {
        void apply(inout index_t index, out index_t result) {
            result = index;
            if (index == (LAT_ARRAY_COUNT - 1))
                index = 0;
            else
                index = index + 1;
        }
    };

    // Index within the current register
    Register<index_t, bit<8>>(1) reg_index;
    RegisterAction<index_t, bit<8>, index_t>(reg_index) inc_index = {
        void apply(inout index_t index, out index_t result) {
            result = index;
            if (index == (LAT_ARRAY_SIZE - 1))
                index = 0;
            else
                index = index + 1;
        }
    };

    // === ts_delta overflow table ===
    // Detect whether the timestamp difference is too large for the histogram
    // table. The table should have a single entry with (32 - n) zero bits
    // followed by n don't care bits. If there is no match, the upper bits of
    // ts_delta are clear, otherwise the value would alias into the wrong bin.

    // Indirect counter for "overflowed" packets
    Counter<bit<64>, index_t>(1, CounterType_t.PACKETS_AND_BYTES) ts_delta_ovfl_counter;

    table tab_ts_delta_ovfl {
        key = {
            ts_delta: ternary;
        }
        actions = { NoAction; }
        default_action = NoAction;
        size = 1;
    }

    // === Latency histogram ===
    // TCAM table with an attached counter for creating a histogram directly in
    // the data plane.

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) lat_hist_counter;

    action count_pkt() {
        lat_hist_counter.count();
    }

    table tab_lat_hist {
        key = {
            ts_delta: ternary;
        }
        actions = { count_pkt; }
        counters = lat_hist_counter;
        size = 1025;
    }

    // === Main ===
    apply {
        if (is_first_pkt.execute(0) == 1)
            reg_rx_first.write(0, rx_timestamp);
        reg_rx_last.write(0, rx_timestamp);

        // Record in array
        index_t array;
        index_t index = inc_index.execute(0);
        if (index == (LAT_ARRAY_SIZE - 1))
            array = inc_array_index.execute(0);
        else
            array = reg_array_index.read(0);
        if (array == 0) reg_lat_array0.write(index, ts_delta);
        if (array == 1) reg_lat_array1.write(index, ts_delta);
        if (array == 2) reg_lat_array2.write(index, ts_delta);
        if (array == 3) reg_lat_array3.write(index, ts_delta);
        if (array == 4) reg_lat_array4.write(index, ts_delta);
        if (array == 5) reg_lat_array5.write(index, ts_delta);
        if (array == 6) reg_lat_array6.write(index, ts_delta);
        if (array == 7) reg_lat_array7.write(index, ts_delta);
        if (array == 8) reg_lat_array8.write(index, ts_delta);
        if (array == 9) reg_lat_array9.write(index, ts_delta);
        if (array == 10) reg_lat_array10.write(index, ts_delta);
        if (array == 11) reg_lat_array11.write(index, ts_delta);
        if (array == 12) reg_lat_array12.write(index, ts_delta);
        if (array == 13) reg_lat_array13.write(index, ts_delta);
        if (array == 14) reg_lat_array14.write(index, ts_delta);
        if (array == 15) reg_lat_array15.write(index, ts_delta);

        // Record in histogram
        if (tab_ts_delta_ovfl.apply().hit) {
            // Increment histogram
            tab_lat_hist.apply();
        } else {
            // Count overflow
            ts_delta_ovfl_counter.count(0);
        }
    }
}

////////////////////////
// Ingress Processing //
////////////////////////

/** Headers **/

const bit<16> UDP_PORT_TIMESTAMP = 0x9999;

header timestamp_h {
    latency_t ts;
}

struct ingress_headers_t {
    pktgen_timer_header_t pktgen_timer;
    ethernet_h            ethernet;
    arp_h                 arp;
    ipv4_h                ipv4;
    ipv6_h                ipv6;
    icmp6_h               icmp6;
    udp_h                 outer_udp;
    sc_headers_t          scion;
    idint_h               idint;
    idint_stack_h         telemetry_stack;
    udp_h                 inner_udp;
    timestamp_h           timestamp;
}

/** Metadata **/

struct ingress_metadata_t {
    bit<16> outer_residual;
}

/** Ingress Parser **/

parser IgParser(packet_in            pkt,
    out ingress_headers_t            hdr,
    out ingress_metadata_t           meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    Checksum() outer_udp_chksum;
    ScionParser() scion_parser;
    value_set<bit<9>>(8) src_ports;
    value_set<bit<4>>(8) timer_app_ids;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            src_ports : parse_pktgen;
            default   : ethernet;
        }
    }

    state parse_pktgen {
        pktgen_timer_header_t pktgen = pkt.lookahead<pktgen_timer_header_t>();
        transition select (pktgen.app_id) {
            timer_app_ids : parse_pktgen_timer;
            default       : reject;
        }
    }

    state parse_pktgen_timer {
        pkt.extract(hdr.pktgen_timer);
        transition ethernet;
    }

    state ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etype) {
            ether_type_t.IPV4 : ipv4;
            ether_type_t.ARP  : arp;
            ether_type_t.IPV6 : ipv6;
            default           : accept;
        }
    }

    state arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);
        transition outer_udp;
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);
        transition select (hdr.ipv6.next_hdr) {
            ip_proto_t.UDP    : outer_udp;
            ip_proto_t.ICMPv6 : icmp6;
        }
    }

    state icmp6 {
        pkt.extract(hdr.icmp6);
        transition accept;
    }

    state outer_udp {
        pkt.extract(hdr.outer_udp);

        outer_udp_chksum.subtract(hdr.outer_udp.src);
        outer_udp_chksum.subtract(hdr.outer_udp.dst);
        outer_udp_chksum.subtract(hdr.outer_udp.chksum);

        // Default port range for SCION BRs is [30042, 30052).
        // Port 50000 and up is used by the scion topology generator.
        transition select (hdr.outer_udp.dst) {
            30042 &&& 0xfffe   : scion; // [30042, 30043]
            30044 &&& 0xfffc   : scion; // [30044, 30047]
            30048 &&& 0xfffc   : scion; // [30048, 30051]
            50000 &&& 0xfff0   : scion; // [50000, 50015]
            default            : accept;
        }
    }

    state scion {
        scion_parser.apply(pkt, hdr.scion, outer_udp_chksum);
        transition select (hdr.scion.common.next_hdr) {
            sc_proto_t.IDINT : idint;
            sc_proto_t.UDP   : inner_udp;
            default          : accept;
        }
    }

    state idint {
        pkt.extract(hdr.idint);
        pkt.extract(hdr.telemetry_stack, (bit<32>)hdr.idint.length * 32);
        transition select (hdr.idint.next_hdr) {
            sc_proto_t.UDP   : inner_udp;
            default          : accept;
        }
    }

    state inner_udp {
        pkt.extract(hdr.inner_udp);

        outer_udp_chksum.subtract_all_and_deposit(meta.outer_residual);

        transition select (hdr.inner_udp.dst) {
            UDP_PORT_TIMESTAMP : timestamp;
            default            : accept;
        }
    }

    state timestamp {
        pkt.extract(hdr.timestamp);
        transition accept;
    }
}

/** Ingress Deparser **/

control IgDeparser(packet_out                       pkt,
    inout ingress_headers_t                         hdr,
    in    ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Checksum() icmp_chksum;
    Checksum() outer_udp_chksum;

    apply {
        // ICMPv6 Checksum
        if (hdr.icmp6.isValid()) {
            hdr.icmp6.chksum = icmp_chksum.update({
                hdr.ipv6.src,
                hdr.ipv6.dst,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmp6.type,
                hdr.icmp6.code,
                hdr.icmp6.router,
                hdr.icmp6.solicited,
                hdr.icmp6.override,
                hdr.icmp6.reserved,
                hdr.icmp6.target,
                hdr.icmp6.opt_type,
                hdr.icmp6.opt_length,
                hdr.icmp6.target_ll
            });
        }

        // Outer UDP checksum
        if (hdr.outer_udp.isValid()) {
            hdr.outer_udp.chksum = outer_udp_chksum.update({
                hdr.outer_udp.src,
                hdr.outer_udp.dst,
                hdr.scion.common.version,
                hdr.scion.common.qos,
                hdr.scion.common.flow_id,
                hdr.timestamp,
                meta.outer_residual
            }, true);
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.icmp6);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.scion);
        pkt.emit(hdr.idint);
        pkt.emit(hdr.telemetry_stack);
        pkt.emit(hdr.inner_udp);
        pkt.emit(hdr.timestamp);
    }
}

/** Ingress Match-Action **/

control Ingress(
    inout ingress_headers_t                         hdr,
    inout ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
#ifndef SINK_IN_EGRESS
    Sink() sink;
#endif

    // === ARP Reply Table ===
    // Responds to ARP requests in order to properly simulate the presence of
    // another device generating the traffic.

    action drop() {
        ig_dprsr_md.drop_ctl = ig_dprsr_md.drop_ctl | 1;
    }

    action arp_reply(mac_addr_t hw_addr) {
        hdr.ethernet.dst = hdr.ethernet.src;
        hdr.ethernet.src = hw_addr;

        hdr.arp.operation = 2;
        hdr.arp.sender_hw_addr = hw_addr;
        hdr.arp.target_hw_addr = hdr.ethernet.dst;
        bit<32> sender;
        sender = hdr.arp.sender_proto_addr;
        hdr.arp.sender_proto_addr = hdr.arp.target_proto_addr;
        hdr.arp.target_proto_addr = sender;

        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        ig_tm_md.bypass_egress = 1;
    }

    table tab_arp_reply {
        key = {
            hdr.arp.hw_type           : exact;
            hdr.arp.proto             : exact;
            hdr.arp.hw_len            : exact;
            hdr.arp.proto_len         : exact;
            hdr.arp.operation         : exact;
            hdr.arp.target_proto_addr : exact;
        }
        actions = {
            drop;
            arp_reply;
        }
        const default_action = drop();
        size = 256;
    }

    // === IPv6 ND Table ===
    // Respond to ICMPv6 neighbor solicitation messages.

    action advertise(mac_addr_t hw_addr) {
        hdr.ethernet.dst = hdr.ethernet.src;
        hdr.ethernet.src = hw_addr;

        hdr.ipv6.dst = hdr.ipv6.src;
        hdr.ipv6.src = hdr.icmp6.target;

        hdr.icmp6.type = icmp6_type.NeighAdvert;
        hdr.icmp6.router = 0;
        hdr.icmp6.solicited = 1;
        hdr.icmp6.override = 1;
        hdr.icmp6.opt_type = 2;
        hdr.icmp6.target_ll = hw_addr;

        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        ig_tm_md.bypass_egress = 1;
    }

    table tab_ipv6_nd {
        key = {
            hdr.icmp6.type     : exact;
            hdr.icmp6.code     : exact;
            hdr.icmp6.opt_type : exact;
            hdr.icmp6.target   : exact;
        }
        actions = {
            drop;
            advertise;
        }
        const default_action = drop();
        size = 256;
    }

    // === Forwarding table ===
    // Forward packets from pktgen to single egress port or multicast group.

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) fwd_counter;

    action set_egress(PortId_t egress_port) {
        fwd_counter.count();
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action multicast(MulticastGroupId_t mcast_grp) {
        fwd_counter.count();
        ig_tm_md.mcast_grp_a = mcast_grp;
    }

    table tab_forward {
        key = {
            hdr.pktgen_timer.pipe_id : exact;
            hdr.pktgen_timer.app_id  : exact;
        }
        actions = {
            set_egress;
            multicast;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        counters = fwd_counter;
        size = 64;
    }

    // === Underlay port modification table ===
    // Allows changing the underlay UDP ports.

    Random<bit<4>>() rng_port;
    bit<16> port_offset;

    action set_underlay_ports(bit<16> src, bit<16> dst) {
        hdr.outer_udp.src = src;
        hdr.outer_udp.dst = dst;
    }

    action randomize_underlay_ports(bit<16> src, bit<16> dst) {
        hdr.outer_udp.src = src + port_offset;
        hdr.outer_udp.dst = dst + port_offset;
    }

    table tab_mod_underlay_ports {
        key = {
            hdr.pktgen_timer.app_id    : ternary;
            hdr.pktgen_timer.batch_id  : ternary;
            hdr.pktgen_timer.packet_id : ternary;
        }
        actions = {
            set_underlay_ports;
            randomize_underlay_ports;
            NoAction;
        }
        const default_action = NoAction;
        size = 512;
    }

    // === Flow ID modification table ===
    // Allow changing the flow ID in the SCION common header.

    Random<bit<20>>() rng_flow_id;

    action set_flow_id(bit<20> flow_id) {
        hdr.scion.common.flow_id = flow_id;
    }

    action randomize_flow_id() {
        hdr.scion.common.flow_id = rng_flow_id.get();
    }

    table tab_mod_flow_id {
        key = {
            hdr.pktgen_timer.app_id    : ternary;
            hdr.pktgen_timer.batch_id  : ternary;
            hdr.pktgen_timer.packet_id : ternary;
        }
        actions = {
            set_flow_id;
            randomize_flow_id;
            NoAction;
        }
        const default_action = NoAction;
        size = 512;
    }

    // === Timestamps ===
    // Store the timestamps of the first and the last sent packet.

    Register<bit<64>, bit<8>>(1) reg_ig_tx_first;
    Register<bit<64>, bit<8>>(1) reg_ig_tx_last;

    // === Main ===
    apply {
        if (hdr.arp.isValid()) {
            // Respond to ARP requests
            tab_arp_reply.apply();
        }
        if (hdr.icmp6.isValid()) {
            // Respond to neighbor solicitations
            tab_ipv6_nd.apply();
        }
        if (hdr.pktgen_timer.isValid()) {
            // TX packet
            if (hdr.timestamp.isValid()) {
                hdr.timestamp.ts = (latency_t)ig_intr_md.ingress_mac_tstamp;

                if (hdr.pktgen_timer.batch_id == 0 && hdr.pktgen_timer.packet_id == 0) {
                    reg_ig_tx_first.write(0, (bit<64>)ig_intr_md.ingress_mac_tstamp);
                }
                reg_ig_tx_last.write(0, (bit<64>)ig_intr_md.ingress_mac_tstamp);

                if (hdr.outer_udp.isValid()) {
                    port_offset = (bit<16>)rng_port.get();
                    tab_mod_underlay_ports.apply();
                }

                if (hdr.scion.common.isValid()) {
                    tab_mod_flow_id.apply();
                }
            }
            tab_forward.apply();
        } else {
            // RX packet
        #ifndef SINK_IN_EGRESS
            // Calculate processing delay if timestamp is available
            if (hdr.timestamp.isValid()) {
                // 32-bit difference at nanosecond precision gives a range of ~4s
                // which should be enough for our use case.
                latency_t ts_delta = (latency_t)ig_intr_md.ingress_mac_tstamp - hdr.timestamp.ts;
                hdr.timestamp.ts = ts_delta;
                sink.apply((bit<64>)ig_intr_md.ingress_mac_tstamp, hdr.timestamp.ts);
            }
        #endif
        }
    }
}

///////////////////////
// Egress Processing //
///////////////////////

/** Headers **/

struct egress_headers_t {
    ethernet_h    ethernet;
    ipv4_h        ipv4;
    ipv6_h        ipv6;
    udp_h         outer_udp;
    sc_headers_t  scion;
    idint_h       idint;
    idint_stack_h telemetry_stack;
    udp_h         inner_udp;
    timestamp_h   timestamp;
}

/** Metadata **/

struct egress_metadata_t {
    bit<16> outer_residual;
}

/** Egress Parser **/

parser EgParser(packet_in           pkt,
    out egress_headers_t            hdr,
    out egress_metadata_t           meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    Checksum() outer_udp_chksum;
    ScionParser() scion_parser;

    state start {
        pkt.extract(eg_intr_md);
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etype) {
            ether_type_t.IPV4 : ipv4;
            ether_type_t.IPV6 : ipv6;
            default           : accept;
        }
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);
        transition outer_udp;
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);
        transition outer_udp;
    }

    state outer_udp {
        pkt.extract(hdr.outer_udp);

        outer_udp_chksum.subtract(hdr.outer_udp.chksum);

        // Default port range for SCION BRs is [30042, 30052).
        // Port 50000 and up is used by the scion topology generator.
        transition select (hdr.outer_udp.dst) {
            30042 &&& 0xfffe   : scion; // [30042, 30043]
            30044 &&& 0xfffc   : scion; // [30044, 30047]
            30048 &&& 0xfffc   : scion; // [30048, 30051]
            50000 &&& 0xfff0   : scion; // [50000, 50015]
            default            : accept;
        }
    }

    state scion {
        scion_parser.apply(pkt, hdr.scion, outer_udp_chksum);
        transition select (hdr.scion.common.next_hdr) {
            sc_proto_t.IDINT : idint;
            sc_proto_t.UDP   : inner_udp;
            default          : accept;
        }
    }

    state idint {
        pkt.extract(hdr.idint);
        pkt.extract(hdr.telemetry_stack, (bit<32>)hdr.idint.length * 32);
        transition select (hdr.idint.next_hdr) {
            sc_proto_t.UDP : inner_udp;
            default        : accept;
        }
    }

    state inner_udp {
        pkt.extract(hdr.inner_udp);

        outer_udp_chksum.subtract_all_and_deposit(meta.outer_residual);

        transition select (hdr.inner_udp.dst) {
            UDP_PORT_TIMESTAMP : timestamp;
            default            : accept;
        }
    }

    state timestamp {
        pkt.extract(hdr.timestamp);
        transition accept;
    }
}

/** Egress Deparser **/

control EgDeparser(packet_out                      pkt,
    inout egress_headers_t                         hdr,
    in    egress_metadata_t                        meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    Checksum() outer_udp_chksum;

    apply {
        // Outer UDP checksum
        if (hdr.outer_udp.isValid()) {
            hdr.outer_udp.chksum = outer_udp_chksum.update({
                hdr.scion.common.version,
                hdr.scion.common.qos,
                hdr.scion.common.flow_id,
                hdr.timestamp,
                meta.outer_residual
            }, true);
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.scion);
        pkt.emit(hdr.idint);
        pkt.emit(hdr.telemetry_stack);
        pkt.emit(hdr.inner_udp);
        pkt.emit(hdr.timestamp);
    }
}

/** Egress Match-Action **/

control Egress(
    inout egress_headers_t                            hdr,
    inout egress_metadata_t                           meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
#ifdef SINK_IN_EGRESS
    Sink() sink;
#endif

    apply {
    #ifndef SINK_IN_EGRESS
        // Only TX packets should ever make it here
        if (hdr.timestamp.isValid()) {
            hdr.timestamp.ts = eg_intr_md.enq_tstamp + eg_intr_md.deq_timedelta;
        }

    #else
        // Calculate processing delay if timestamp is available
        if (hdr.timestamp.isValid()) {
            // 32-bit difference at nanosecond precision gives a range of ~4s
            // which should be enough for our use case.
            latency_t ts_delta = (latency_t)eg_prsr_md.global_tstamp - hdr.timestamp.ts;
            hdr.timestamp.ts = ts_delta;
            sink.apply((bit<64>)eg_prsr_md.global_tstamp, hdr.timestamp.ts);
        }

        // Drop packet
        eg_dprsr_md.drop_ctl = 1;

    #endif
    }
}

//////////////
// Pipeline //
//////////////

Pipeline(
    IgParser(),
    Ingress(),
    IgDeparser(),
    EgParser(),
    Egress(),
    EgDeparser()
) pktgen;

Switch(pktgen) main;
