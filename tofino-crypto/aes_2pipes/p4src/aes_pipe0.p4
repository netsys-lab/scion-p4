// SPDX-License-Identifier: AGPL-3.0-or-later
#include <core.p4>
#include <tna.p4>

#include "include/parser.p4"
#include "include/aes.p4"


///////////////////////
// Egress Processing //
///////////////////////

/** Egress Parser **/

parser EgParser(packet_in           pkt,
    out aes_headers_t               hdr,
    out aes_metadata_t              meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    AesParser() aes_parser;

    state start {
        pkt.extract(eg_intr_md);
        aes_parser.apply(pkt, hdr, meta);
        transition accept;
    }
}

/** Egress Deparser **/

control EgDeparser(packet_out                      pkt,
    inout aes_headers_t                            hdr,
    in    aes_metadata_t                           meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/** Egress Match-Action **/

control Egress(
    inout aes_headers_t                               hdr,
    inout aes_metadata_t                              meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    // === Local variables ===

    // AES block 0 key expansion
    bit<8> byte0_b0 = 0;
    bit<8> byte1_b0 = 0;
    bit<8> byte2_b0 = 0;
    bit<8> byte3_b0 = 0;

    // AES block 1 key expansion
    bit<8> byte0_b1 = 0;
    bit<8> byte1_b1 = 0;
    bit<8> byte2_b1 = 0;
    bit<8> byte3_b1 = 0;

    // AES block 0 temporaries
    bit<32> col0_b0 = 0;
    bit<32> col1_b0 = 0;
    bit<32> col2_b0 = 0;
    bit<32> col3_b0 = 0;

    // AES block 1 temporaries
    bit<32> col0_b1 = 0;
    bit<32> col1_b1 = 0;
    bit<32> col2_b1 = 0;
    bit<32> col3_b1 = 0;

    // === Actions ===

    def_add_byte0(0, hdr.key)
    def_add_byte1(0, hdr.key)
    def_add_byte2(0, hdr.key)
    def_add_byte3(0, hdr.key)

    def_add_byte0(1, meta.key)
    def_add_byte1(1, meta.key)
    def_add_byte2(1, meta.key)
    def_add_byte3(1, meta.key)

    def_set_col0(0)
    def_set_col1(0)
    def_set_col2(0)
    def_set_col3(0)
    def_add_col0(0)
    def_add_col1(0)
    def_add_col2(0)
    def_add_col3(0)

    def_set_col0(1)
    def_set_col1(1)
    def_set_col2(1)
    def_set_col3(1)
    def_add_col0(1)
    def_add_col1(1)
    def_add_col2(1)
    def_add_col3(1)

    // === S-Tables for Key Expansion ===

    S_TABLES_KEY_EXP(0, 1, hdr.key)
    S_TABLES_KEY_EXP(0, 2, hdr.key)
    S_TABLES_KEY_EXP(0, 3, hdr.key)
    S_TABLES_KEY_EXP(0, 4, hdr.key)

    S_TABLES_KEY_EXP(1, 1, meta.key)
    S_TABLES_KEY_EXP(1, 2, meta.key)
    S_TABLES_KEY_EXP(1, 3, meta.key)

    // === T-Tables ===

    T_TABLES(0, 1, hdr.block0)
    T_TABLES(0, 2, hdr.block0)
    T_TABLES(0, 3, hdr.block0)

    T_TABLES(1, 1, hdr.block1)
    T_TABLES(1, 2, hdr.block1)
    T_TABLES(1, 3, hdr.block1)

    // === Main ===

    apply {
        if (hdr.key.isValid()) {
            // Initialization
            // XOR round key with state
            if (hdr.block0.isValid()) ADD_ROUND_KEY(0, hdr.key);
            if (hdr.block1.isValid()) ADD_ROUND_KEY(1, meta.key);

            // Calculate key for round 1
            EXPAND_KEY(0, 1, hdr.key);
            EXPAND_KEY(1, 1, meta.key);

            // Round 1
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 1, hdr.block0);
                ADD_ROUND_KEY(0, hdr.key);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 1, hdr.block1);
                ADD_ROUND_KEY(1, meta.key);
            }

            // Calculate key for round 2
            EXPAND_KEY(0, 2, hdr.key);
            EXPAND_KEY(1, 2, meta.key);

            // Round 2
            if (hdr.block0.isValid())  {
                APPLY_T_TABLES(0, 2, hdr.block0);
                ADD_ROUND_KEY(0, hdr.key);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 2, hdr.block1);
                ADD_ROUND_KEY(1, meta.key);
            }

            // Calculate key for round 3
            EXPAND_KEY(0, 3, hdr.key);
            EXPAND_KEY(1, 3, meta.key);

            // Round 3
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 3, hdr.block0);
                ADD_ROUND_KEY(0, hdr.key);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 3, hdr.block1);
                ADD_ROUND_KEY(1, meta.key);
            }

            // Calculate key for round 4
            EXPAND_KEY(0, 4, hdr.key);
        }
    }
}


////////////////////////
// Ingress Processing //
////////////////////////

/** Ingress Parser **/

parser IgParser(packet_in            pkt,
    out aes_headers_t                hdr,
    out aes_metadata_t               meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    AesParser() aes_parser;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        aes_parser.apply(pkt, hdr, meta);
        transition accept;
    }
}

/** Ingress Deparser **/

control IgDeparser(packet_out                       pkt,
    inout aes_headers_t                             hdr,
    in    aes_metadata_t                            meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/** Ingress Match-Action **/

control Ingress(
    inout aes_headers_t                             hdr,
    inout aes_metadata_t                            meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    // === Local variables ===

    // AES block 0 key expansion
    bit<8> byte0_b0 = 0;
    bit<8> byte1_b0 = 0;
    bit<8> byte2_b0 = 0;
    bit<8> byte3_b0 = 0;

    // AES block 1 key expansion
    bit<8> byte0_b1 = 0;
    bit<8> byte1_b1 = 0;
    bit<8> byte2_b1 = 0;
    bit<8> byte3_b1 = 0;

    // AES block 0 temporaries
    bit<32> col0_b0 = 0;
    bit<32> col1_b0 = 0;
    bit<32> col2_b0 = 0;
    bit<32> col3_b0 = 0;

    // AES block 1 temporaries
    bit<32> col0_b1 = 0;
    bit<32> col1_b1 = 0;
    bit<32> col2_b1 = 0;
    bit<32> col3_b1 = 0;

    // === Actions ===

    action set_egress(PortId_t egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    def_add_byte0(0, hdr.key)
    def_add_byte1(0, hdr.key)
    def_add_byte2(0, hdr.key)
    def_add_byte3(0, hdr.key)

    def_add_byte0(1, meta.key)
    def_add_byte1(1, meta.key)
    def_add_byte2(1, meta.key)
    def_add_byte3(1, meta.key)

    def_set_col0(0)
    def_set_col1(0)
    def_set_col2(0)
    def_set_col3(0)
    def_add_col0(0)
    def_add_col1(0)
    def_add_col2(0)
    def_add_col3(0)

    def_set_col0(1)
    def_set_col1(1)
    def_set_col2(1)
    def_set_col3(1)
    def_add_col0(1)
    def_add_col1(1)
    def_add_col2(1)
    def_add_col3(1)

    // === Tables ===

    table tab_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = { set_egress; NoAction; }
        default_action = NoAction();
        size = 512;
    }

    // === S-Tables for Key Expansion ===

    S_TABLES_KEY_EXP(0, 5, hdr.key)
    S_TABLES_KEY_EXP(0, 6, hdr.key)

    S_TABLES_KEY_EXP(1, 5, meta.key)

    // === T-Tables ===

    T_TABLES(0, 4, hdr.block0)
    T_TABLES(0, 5, hdr.block0)

    T_TABLES(1, 4, hdr.block1)
    T_TABLES(1, 5, hdr.block1)

    // === Main ===

    apply {
        if (hdr.key.isValid()) {
            // Round 4
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 4, hdr.block0);
                ADD_ROUND_KEY(0, hdr.key);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 4, hdr.block1);
                ADD_ROUND_KEY(1, meta.key);
            }

            // Calculate key for round 5
            EXPAND_KEY(0, 5, hdr.key);
            EXPAND_KEY(1, 5, meta.key);

            // Round 5
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 5, hdr.block0);
                ADD_ROUND_KEY(0, hdr.key);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 5, hdr.block1);
                ADD_ROUND_KEY(1, meta.key);
            }

            // Calculate key for round 6
            EXPAND_KEY(0, 6, hdr.key);
        }

        // Forward to next pipe
        tab_forward.apply();
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
) aes0;

Switch(aes0) main;
