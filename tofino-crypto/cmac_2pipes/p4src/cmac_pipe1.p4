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

    tab_bB_rR_key(0, 7)
    tab_bB_rR_key(0, 8)
    tab_bB_rR_key(0, 9)

    tab_bB_rR_key(1, 7)
    tab_bB_rR_key(1, 8)
    tab_bB_rR_key(1, 9)

    // === T-Tables ===

    T_TABLES(0, 7, hdr.block0)
    T_TABLES(0, 8, hdr.block0)
    T_TABLES(0, 9, hdr.block0)

    T_TABLES(1, 7, hdr.block1)
    T_TABLES(1, 8, hdr.block1)
    T_TABLES(1, 9, hdr.block1)

    // === Main ===

    apply {
        if (hdr.meta.isValid()) {
            // Round 7
            if (hdr.block0.isValid()) {
                APPLY_T_TABLES(0, 7, hdr.block0);
                ADD_ROUND_KEY(0, 7);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 7, hdr.block1);
                ADD_ROUND_KEY(1, 7);
            }

            // Round 8
            if (hdr.block0.isValid())  {
                APPLY_T_TABLES(0, 8, hdr.block0);
                ADD_ROUND_KEY(0, 8);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 8, hdr.block1);
                ADD_ROUND_KEY(1, 8);
            }

            // Round 9
            if (hdr.block0.isValid())  {
                APPLY_T_TABLES(0, 9, hdr.block0);
                ADD_ROUND_KEY(0, 9);
            }
            if (hdr.block1.isValid()) {
                APPLY_T_TABLES(1, 9, hdr.block1);
                ADD_ROUND_KEY(1, 9);
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
        // remove bridge header
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

    // === Key Tables ===

    tab_bB_rR_key(0, 10)
    tab_bB_rR_key(1, 10)

    // === S-Tables for Round 10 ===

    S_TABLES(0, 10, hdr.block0)
    S_TABLES(1, 10, hdr.block1)

    // === Main ===

    apply {
        if (hdr.meta.isValid()) {
            bool pass = true;

            // Round 10
            if (hdr.block0.isValid()) {
                APPLY_S_TABLES(0, 10, hdr.block0);
                ADD_ROUND_KEY(0, 10);
                if (hdr.block0.c0 != hdr.block0.cmac[47:16])
                    pass = false;
                if (hdr.block0.c1[31:16] != hdr.block0.cmac[15:0])
                    pass = false;
            }
            if (hdr.block1.isValid()) {
                APPLY_S_TABLES(1, 10, hdr.block1);
                ADD_ROUND_KEY(1, 10);
                if (hdr.block1.c0 != hdr.block1.cmac[47:16])
                    pass = false;
                if (hdr.block1.c1[31:16] != hdr.block1.cmac[15:0])
                    pass = false;
            }

            if (pass) {
                ig_tm_md.ucast_egress_port = hdr.meta.egress_port;
            }
        }
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
) cmac1;

Switch(cmac1) main;
