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
    out cmac_headers_t              hdr,
    out cmac_metadata_t             meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    CmacParser() cmac_parser;

    state start {
        pkt.extract(eg_intr_md);
        cmac_parser.apply(pkt, hdr, meta);
        transition accept;
    }
}

/** Egress Deparser **/

control EgDeparser(packet_out                      pkt,
    inout cmac_headers_t                           hdr,
    in    cmac_metadata_t                          meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/** Egress Match-Action **/

control Egress(
    inout cmac_headers_t                              hdr,
    inout cmac_metadata_t                             meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    // === Local variables ===

    bit<4> key_b0 = 0; // key index for first block
    bit<4> key_b1 = 0; // key index for second block

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

    def_add_key(0, hdr.block0)
    def_add_key(1, hdr.block1)

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

    // === Key Tables ===

    tab_bB_rR_key(0, 0)
    tab_bB_rR_key(0, 1)
    tab_bB_rR_key(0, 2)
    tab_bB_rR_key(0, 3)

    tab_bB_rR_key(1, 0)
    tab_bB_rR_key(1, 1)
    tab_bB_rR_key(1, 2)
    tab_bB_rR_key(1, 3)

    // === T-Tables ===

    T_TABLES(0, 1, hdr.block0)
    T_TABLES(0, 2, hdr.block0)
    T_TABLES(0, 3, hdr.block0)

    T_TABLES(1, 1, hdr.block1)
    T_TABLES(1, 2, hdr.block1)
    T_TABLES(1, 3, hdr.block1)

    // === Main ===

    apply {
        if (hdr.meta.isValid()) {
            // Initialization
            // Key table 0 contains the original key XOR the CMAC subkey
            if (hdr.block0.isValid()) ADD_ROUND_KEY(0, 0);
            if (hdr.block1.isValid()) ADD_ROUND_KEY(1, 0);

            // Round 1
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 1, hdr.block0);
                ADD_ROUND_KEY(0, 1);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 1, hdr.block1);
                ADD_ROUND_KEY(1, 1);
            }

            // Round 2
            if (hdr.block0.isValid())  {
                APPLY_T_TABLES(0, 2, hdr.block0);
                ADD_ROUND_KEY(0, 2);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 2, hdr.block1);
                ADD_ROUND_KEY(1, 2);
            }

            // Round 3
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 3, hdr.block0);
                ADD_ROUND_KEY(0, 3);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 3, hdr.block1);
                ADD_ROUND_KEY(1, 3);
            }
        }
    }
}


////////////////////////
// Ingress Processing //
////////////////////////

/** Ingress Parser **/

parser IgParser(packet_in            pkt,
    out cmac_headers_t               hdr,
    out cmac_metadata_t              meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    CmacParser() cmac_parser;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        cmac_parser.apply(pkt, hdr, meta);
        transition accept;
    }
}

/** Ingress Deparser **/

control IgDeparser(packet_out                       pkt,
    inout cmac_headers_t                            hdr,
    in    cmac_metadata_t                           meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/** Ingress Match-Action **/

control Ingress(
    inout cmac_headers_t                            hdr,
    inout cmac_metadata_t                           meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    // === Local variables ===

    bit<4> key_b0 = 0; // key index for first block
    bit<4> key_b1 = 0; // key index for second block

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

    def_add_key(0, hdr.block0)
    def_add_key(1, hdr.block1)

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

    // === Key Tables ===

    tab_bB_rR_key(0, 4)
    tab_bB_rR_key(0, 5)
    tab_bB_rR_key(0, 6)

    tab_bB_rR_key(1, 4)
    tab_bB_rR_key(1, 5)
    tab_bB_rR_key(1, 6)

    // === T-Tables ===

    T_TABLES(0, 4, hdr.block0)
    T_TABLES(0, 5, hdr.block0)
    T_TABLES(0, 6, hdr.block0)

    T_TABLES(1, 4, hdr.block1)
    T_TABLES(1, 5, hdr.block1)
    T_TABLES(1, 6, hdr.block1)

    // === Main ===

    apply {
        if (hdr.meta.isValid()) {
            // Round 4
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 4, hdr.block0);
                ADD_ROUND_KEY(0, 4);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 4, hdr.block1);
                ADD_ROUND_KEY(1, 4);
            }

            // Round 5
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 5, hdr.block0);
                ADD_ROUND_KEY(0, 5);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 5, hdr.block1);
                ADD_ROUND_KEY(1, 5);
            }

            // Round 6
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 6, hdr.block0);
                ADD_ROUND_KEY(0, 6);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 6, hdr.block1);
                ADD_ROUND_KEY(1, 6);
            }
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
) cmac0;

Switch(cmac0) main;
