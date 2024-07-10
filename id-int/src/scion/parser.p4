#ifndef SCION_PARSER_P4_GUARD
#define SCION_PARSER_P4_GUARD

#include <core.p4>
#include <tna.p4>

#include "headers.p4"
#include "../idint/parser.p4"


///////////////////
// ScionBrParser //
///////////////////

// Parser for the external bridge header
parser ScionBrParser(packet_in pkt,
    out sc_bridge_t            bridge)
{
    state start {
        pkt.extract(bridge.meta);
        transition select (bridge.meta.check_first_hf) {
            0: accept;
            1: first_hf;
        }
    }

    state first_hf {
        pkt.extract(bridge.info0);
        pkt.extract(bridge.hf0);
        transition select (bridge.meta.check_second_hf) {
            0: accept;
            1: second_hf;
        }
    }

    state second_hf {
        pkt.extract(bridge.info1);
        pkt.extract(bridge.hf1);
        transition accept;
    }
}

//////////////////////////
// ScionBrDiscardParser //
//////////////////////////

// Parser for the external bridge header that discards the hop fields.
// On the seconds ingress of the packet we do not need the copied hop fields anymore an can skip
// over them.
parser ScionBrDiscardParser(packet_in pkt,
    out sc_bridge_meta_h              bridge_meta)
{
    state start {
        pkt.extract(bridge_meta);
        transition select (bridge_meta.check_first_hf) {
            0: accept;
            1: first_hf;
        }
    }

    state first_hf {
        pkt.extract<sc_info_h>(_);
        pkt.extract<sc_hop_h>(_);
        transition select (bridge_meta.check_second_hf) {
            0: accept;
            1: second_hf;
        }
    }

    state second_hf {
        pkt.extract<sc_info_h>(_);
        pkt.extract<sc_hop_h>(_);
        transition accept;
    }
}

/////////////////
// ScionParser //
/////////////////

// Parser for the SCION header without extensions
parser ScionParser(packet_in pkt,
    out   sc_headers_t       hdr,
    inout sc_bridge_t        bridge,
    out   sc_meta_t          meta)
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
        counter.set(hdr.common.hdr_len, SC_MAC_HDR_LEN / 4, 0, 0, 0);
        counter.decrement(SC_COMMON_HDR_LEN / 4);
        transition host_address;
    }

    ////////////////////
    // Host Addresses //
    ////////////////////

    state host_address {
        transition select (hdr.common.host_type_len) {
            0x03 &&& 0x0F: dst_host_4;
            0x0F &&& 0x0F: dst_host_16;
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
            0x30 &&& 0xF0: src_host_4;
            0xF0 &&& 0xF0: src_host_16;
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
        }
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

    state hop_fields {
        transition select (hdr.path_meta.curr_hf) {
            0: hf0;
            1: hf1;
            2: hf2;
            3: hf3;
            4: hf4;
            5: hf5;
            6: hf6;
            7: hf7;
        }
    }

    ////////////////////
    // Current HF = 0 //
    ////////////////////

    state hf0 {
        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(2 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf0_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf0_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf0_rem_hf;
            true : accept;
        }
    }

    // Extract the remaining hop fields
    state hf0_rem_hf {
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        pkt.extract(hdr.hop.next);
        transition select (counter.is_negative()) {
            false: hf0_rem_hf;
            true : accept;
        }
    }

    ////////////////////
    // Current HF = 1 //
    ////////////////////

    state hf1 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(3 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf1_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf1_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf1_rem_hf;
            true : accept;
        }
    }

    // Extract the remaining hop fields
    state hf1_rem_hf {
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        pkt.extract(hdr.hop.next);
        transition select (counter.is_negative()) {
            false: hf1_rem_hf;
            true : accept;
        }
    }

    ////////////////////
    // Current HF = 2 //
    ////////////////////

    state hf2 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(4 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf2_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf2_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf2_rem_hf;
            true : accept;
        }
    }

    // Extract the remaining hop fields
    state hf2_rem_hf {
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        pkt.extract(hdr.hop.next);
        transition select (counter.is_negative()) {
            false: hf2_rem_hf;
            true : accept;
        }
    }

    ////////////////////
    // Current HF = 3 //
    ////////////////////

    state hf3 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(5 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf3_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf3_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf3_rem_hf;
            true : accept;
        }
    }

    // Extract the remaining hop fields
    state hf3_rem_hf {
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        pkt.extract(hdr.hop.next);
        transition select (counter.is_negative()) {
            false: hf3_rem_hf;
            true : accept;
        }
    }

    ////////////////////
    // Current HF = 4 //
    ////////////////////

    state hf4 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(6 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf4_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf4_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf4_rem_hf;
            true : accept;
        }
    }

    // Extract the remaining hop fields
    state hf4_rem_hf {
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        pkt.extract(hdr.hop.next);
        transition select (counter.is_negative()) {
            false: hf4_rem_hf;
            true : accept;
        }
    }

    ////////////////////
    // Current HF = 5 //
    ////////////////////

    state hf5 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(7 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf5_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf5_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf5_rem_hf;
            true : accept;
        }
    }

    // Extract the remaining hop fields
    state hf5_rem_hf {
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        pkt.extract(hdr.hop.next);
        transition select (counter.is_negative()) {
            false: hf5_rem_hf;
            true : accept;
        }
    }

    ////////////////////
    // Current HF = 6 //
    ////////////////////

    state hf6 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        // Decide whether the next hop field can be extracted
        counter.decrement(8 * SC_HOP_FIELD_LEN / 4);
        transition select (counter.is_negative()) {
            false: hf6_second_hf;
            true : accept;
        }
    }

    // Extract a second hop field
    state hf6_second_hf {
        bridge.hf1 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);
        counter.decrement(SC_HOP_FIELD_LEN / 4);
        transition accept;
    }

    ////////////////////
    // Current HF = 7 //
    ////////////////////

    state hf7 {
        // Skip to current HF
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);
        pkt.extract(hdr.hop.next);

        // Extract current HF twice
        bridge.hf0 = pkt.lookahead<sc_hop_h>();
        pkt.extract(hdr.hop.next);

        transition accept;
    }
}

#endif // SCION_PARSER_P4_GUARD
