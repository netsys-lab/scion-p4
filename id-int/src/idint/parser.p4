#ifndef IDINT_PARSER_P4_GUARD
#define IDINT_PARSER_P4_GUARD

#include <core.p4>
#include <tna.p4>

#include "headers.p4"


/////////////////
// MetadataPar //
/////////////////

// Parser for variable-length metadata in stack entries
parser MetadataPar(packet_in    pkt,
    in  idint_metadata_header_h hdr,
    out idint_telemetry_t       data)
{
    state start {
        transition node_count_and_id;
    }

    /* Fixed-length metadata */

    state node_count_and_id {
        transition select(hdr.flags_and_meta_len) {
            0x0000 &&& 0xC000: ingr_egrs_iface;
            0x4000 &&& 0xC000: extr_node_count;
            0x8000 &&& 0xC000: extr_node_id;
            0xC000 &&& 0xC000: extr_node_count_and_id;
        }
    }

    state extr_node_count {
        pkt.extract(data.node_count);
        transition ingr_egrs_iface;
    }

    state extr_node_id {
        pkt.extract(data.node_id);
        transition ingr_egrs_iface;
    }

    state extr_node_count_and_id {
        pkt.extract(data.node_count);
        pkt.extract(data.node_id);
        transition ingr_egrs_iface;
    }

    state ingr_egrs_iface {
        transition select(hdr.flags_and_meta_len) {
            0x0000 &&& 0x3000: metadata1;
            0x1000 &&& 0x3000: extr_ingr_iface;
            0x2000 &&& 0x3000: extr_egrs_iface;
            0x3000 &&& 0x3000: extr_ingr_egrs_iface;
        }
    }

    state extr_ingr_iface {
        pkt.extract(data.ingress_iface);
        transition metadata1;
    }

    state extr_egrs_iface {
        pkt.extract(data.egress_iface);
        transition metadata1;
    }

    state extr_ingr_egrs_iface {
        pkt.extract(data.ingress_iface);
        pkt.extract(data.egress_iface);
        transition metadata1;
    }

    /* Variable-length metadata */

    state metadata1 {
        transition select(hdr.flags_and_meta_len) {
            0x0000 &&& 0x0E00: metadata2;
            0x0800 &&& 0x0E00: extract_metadata1_2b;
            0x0A00 &&& 0x0E00: extract_metadata1_4b;
            0x0C00 &&& 0x0E00: extract_metadata1_6b;
            0x0E00 &&& 0x0E00: extract_metadata1_8b;
        }
    }

    state extract_metadata1_2b {
        pkt.extract(data.data1.meta2);
        transition metadata2;
    }

    state extract_metadata1_4b {
        pkt.extract(data.data1.meta4);
        transition metadata2;
    }

    state extract_metadata1_6b {
        pkt.extract(data.data1.meta6);
        transition metadata2;
    }

    state extract_metadata1_8b {
        pkt.extract(data.data1.meta8);
        transition metadata2;
    }

    state metadata2 {
        transition select(hdr.flags_and_meta_len) {
            0x0000 &&& 0x01C0: metadata3;
            0x0100 &&& 0x01C0: extract_metadata2_2b;
            0x0140 &&& 0x01C0: extract_metadata2_4b;
            0x0180 &&& 0x01C0: extract_metadata2_6b;
            0x01C0 &&& 0x01C0: extract_metadata2_8b;
        }
    }

    state extract_metadata2_2b {
        pkt.extract(data.data2.meta2);
        transition metadata3;
    }

    state extract_metadata2_4b {
        pkt.extract(data.data2.meta4);
        transition metadata3;
    }

    state extract_metadata2_6b {
        pkt.extract(data.data2.meta6);
        transition metadata3;
    }

    state extract_metadata2_8b {
        pkt.extract(data.data2.meta8);
        transition metadata3;
    }

    state metadata3 {
        transition select(hdr.flags_and_meta_len) {
            0x0000 &&& 0x0038: metadata4;
            0x0020 &&& 0x0038: extract_metadata3_2b;
            0x0028 &&& 0x0038: extract_metadata3_4b;
            0x0030 &&& 0x0038: extract_metadata3_6b;
            0x0038 &&& 0x0038: extract_metadata3_8b;
        }
    }

    state extract_metadata3_2b {
        pkt.extract(data.data3.meta2);
        transition metadata4;
    }

    state extract_metadata3_4b {
        pkt.extract(data.data3.meta4);
        transition metadata4;
    }

    state extract_metadata3_6b {
        pkt.extract(data.data3.meta6);
        transition metadata4;
    }

    state extract_metadata3_8b {
        pkt.extract(data.data3.meta8);
        transition metadata4;
    }

    state metadata4 {
        transition select(hdr.flags_and_meta_len) {
            0x0000 &&& 0x0007: accept;
            0x0004 &&& 0x0007: extract_metadata4_2;
            0x0005 &&& 0x0007: extract_metadata4_4;
            0x0006 &&& 0x0007: extract_metadata4_6;
            0x0007 &&& 0x0007: extract_metadata4_8;
        }
    }

    state extract_metadata4_2 {
        pkt.extract(data.data4.meta2);
        transition accept;
    }

    state extract_metadata4_4 {
        pkt.extract(data.data4.meta4);
        transition accept;
    }

    state extract_metadata4_6 {
        pkt.extract(data.data4.meta6);
        transition accept;
    }

    state extract_metadata4_8 {
        pkt.extract(data.data4.meta8);
        transition accept;
    }
}

/////////////////
// IdIntParser //
/////////////////

// ID-INT telemetry header parser
parser IdIntParser(packet_in pkt,
    out idint_ig_headers_t   hdr)
{
    /* Extract common header and verifier address */

    state start {
        pkt.extract(hdr.hdr);
        transition select(hdr.hdr.mode_and_verif) {
            0x00 &&& 0xC0: verifier;
            default: parse_telemetry;
        }
    }

    state verifier {
        pkt.extract(hdr.verif);
        transition select(hdr.hdr.mode_and_verif) {
            0x00 &&& 0x03: extr_verif_4b;
            0x03 &&& 0x03: extr_verif_16b;
        }
    }

    @critical
    state extr_verif_4b {
        pkt.extract(hdr.verif_host.host4);
        transition parse_telemetry;
    }

    @critical
    state extr_verif_16b {
        pkt.extract(hdr.verif_host.host16);
        transition parse_telemetry;
    }

    /* Parse telemetry */

    state parse_telemetry {
        pkt.extract(hdr.md_hdr);
        transition select(hdr.md_hdr.encrypted) {
            0: parse_metadata;
            1: extract_nonce;
        }
    }

    state extract_nonce {
        pkt.extract<idint_nonce_h>(_);
        transition parse_metadata;
    }

    state parse_metadata {
        MetadataPar.apply(pkt, hdr.md_hdr, hdr.metadata);
        pkt.extract(hdr.mac);
        transition accept;
    }
}

///////////////////
// IdIntBrParser //
///////////////////

// Parser for the ID-INT bridge header
parser IdIntBrParser(packet_in pkt,
    out idint_bridge_eg_t      bridge)
{
    state start {
        pkt.extract(bridge.ig_meta);
        pkt.extract(bridge.key_hdr);
        pkt.extract(bridge.md_hdr);
        pkt.extract(bridge.mac);
        transition node_count_and_id;
    }

    state node_count_and_id {
        transition select(bridge.md_hdr.flags_and_meta_len) {
            0x0000 &&& 0xC000: ingr_egrs_iface;
            0x4000 &&& 0xC000: extr_node_count;
            0x8000 &&& 0xC000: extr_node_id;
            0xC000 &&& 0xC000: extr_node_count_and_id;
        }
    }

    state extr_node_count {
        pkt.extract(bridge.metadata.node_count);
        transition ingr_egrs_iface;
    }

    state extr_node_id {
        pkt.extract(bridge.metadata.node_id);
        transition ingr_egrs_iface;
    }

    state extr_node_count_and_id {
        pkt.extract(bridge.metadata.node_count);
        pkt.extract(bridge.metadata.node_id);
        transition ingr_egrs_iface;
    }

    state ingr_egrs_iface {
        transition select(bridge.md_hdr.flags_and_meta_len) {
            0x0000 &&& 0x3000: metadata1;
            0x1000 &&& 0x3000: extr_ingr_iface;
            0x2000 &&& 0x3000: extr_egrs_iface;
            0x3000 &&& 0x3000: extr_ingr_egrs_iface;
        }
    }

    state extr_ingr_iface {
        pkt.extract(bridge.metadata.ingress_iface);
        transition metadata1;
    }

    state extr_egrs_iface {
        pkt.extract(bridge.metadata.egress_iface);
        transition metadata1;
    }

    state extr_ingr_egrs_iface {
        pkt.extract(bridge.metadata.ingress_iface);
        pkt.extract(bridge.metadata.egress_iface);
        transition metadata1;
    }

    state metadata1 {
        transition select(bridge.md_hdr.flags_and_meta_len) {
            0x0000 &&& 0x0E00: metadata2;
            0x0800 &&& 0x0E00: extract_metadata1_2b;
            0x0A00 &&& 0x0E00: extract_metadata1_4b;
            0x0C00 &&& 0x0E00: extract_metadata1_6b;
            0x0E00 &&& 0x0E00: extract_metadata1_8b;
        }
    }

    state extract_metadata1_2b {
        pkt.advance(6 * 8);
        pkt.extract(bridge.metadata.data1.meta2);
        transition metadata2;
    }

    state extract_metadata1_4b {
        pkt.advance(4 * 8);
        pkt.extract(bridge.metadata.data1.meta4);
        transition metadata2;
    }

    state extract_metadata1_6b {
        pkt.advance(2 * 8);
        pkt.extract(bridge.metadata.data1.meta6);
        transition metadata2;
    }

    state extract_metadata1_8b {
        pkt.extract(bridge.metadata.data1.meta8);
        transition metadata2;
    }

    state metadata2 {
        transition select(bridge.md_hdr.flags_and_meta_len) {
            0x0000 &&& 0x0E00: metadata3;
            0x0800 &&& 0x0E00: extract_metadata2_2b;
            0x0A00 &&& 0x0E00: extract_metadata2_4b;
            0x0C00 &&& 0x0E00: extract_metadata2_6b;
            0x0E00 &&& 0x0E00: extract_metadata2_8b;
        }
    }

    state extract_metadata2_2b {
        pkt.advance(6 * 8);
        pkt.extract(bridge.metadata.data2.meta2);
        transition metadata3;
    }

    state extract_metadata2_4b {
        pkt.advance(4 * 8);
        pkt.extract(bridge.metadata.data2.meta4);
        transition metadata3;
    }

    state extract_metadata2_6b {
        pkt.advance(2 * 8);
        pkt.extract(bridge.metadata.data2.meta6);
        transition metadata3;
    }

    state extract_metadata2_8b {
        pkt.extract(bridge.metadata.data2.meta8);
        transition metadata3;
    }

    state metadata3 {
        transition select(bridge.md_hdr.flags_and_meta_len) {
            0x0000 &&& 0x0E00: metadata4;
            0x0800 &&& 0x0E00: extract_metadata3_2b;
            0x0A00 &&& 0x0E00: extract_metadata3_4b;
            0x0C00 &&& 0x0E00: extract_metadata3_6b;
            0x0E00 &&& 0x0E00: extract_metadata3_8b;
        }
    }

    state extract_metadata3_2b {
        pkt.advance(6 * 8);
        pkt.extract(bridge.metadata.data3.meta2);
        transition metadata4;
    }

    state extract_metadata3_4b {
        pkt.advance(4 * 8);
        pkt.extract(bridge.metadata.data3.meta4);
        transition metadata4;
    }

    state extract_metadata3_6b {
        pkt.advance(2 * 8);
        pkt.extract(bridge.metadata.data3.meta6);
        transition metadata4;
    }

    state extract_metadata3_8b {
        pkt.extract(bridge.metadata.data3.meta8);
        transition metadata4;
    }

    state metadata4 {
        transition select(bridge.md_hdr.flags_and_meta_len) {
            0x0000 &&& 0x0E00: accept;
            0x0800 &&& 0x0E00: extract_metadata4_2b;
            0x0A00 &&& 0x0E00: extract_metadata4_4b;
            0x0C00 &&& 0x0E00: extract_metadata4_6b;
            0x0E00 &&& 0x0E00: extract_metadata4_8b;
        }
    }

    state extract_metadata4_2b {
        pkt.advance(6 * 8);
        pkt.extract(bridge.metadata.data4.meta2);
        transition accept;
    }

    state extract_metadata4_4b {
        pkt.advance(4 * 8);
        pkt.extract(bridge.metadata.data4.meta4);
        transition accept;
    }

    state extract_metadata4_6b {
        pkt.advance(2 * 8);
        pkt.extract(bridge.metadata.data4.meta6);
        transition accept;
    }

    state extract_metadata4_8b {
        pkt.extract(bridge.metadata.data4.meta8);
        transition accept;
    }
}

#endif // IDINT_PARSER_P4_GUARD
