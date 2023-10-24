// SPDX-License-Identifier: AGPL-3.0-or-later
#include <core.p4>
#include <tna.p4>


////////////////////////
// Ingress Processing //
////////////////////////

/** Headers **/

struct ingress_headers_t {
}

/** Metadata **/

struct ingress_metadata_t {
}

/** Ingress Parser **/

parser IgParser(packet_in         pkt,
    out ingress_headers_t        hdr,
    out ingress_metadata_t       meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

/** Ingress Deparser **/

control IgDeparser(packet_out                       pkt,
    inout ingress_headers_t                         hdr,
    in    ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
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
    action set_egress(PortId_t egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table tab_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = { set_egress; NoAction; }
        default_action = NoAction();
        size = 512;
    }

    apply {
        tab_forward.apply();
    }
}

///////////////////////
// Egress Processing //
///////////////////////

/** Headers **/

struct egress_headers_t {
}

/** Metadata **/

struct egress_metadata_t {
}

/** Egress Parser **/

parser EgParser(packet_in           pkt,
    out egress_headers_t            hdr,
    out egress_metadata_t           meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        transition accept;
    }
}

/** Egress Deparser **/

control EgDeparser(packet_out                      pkt,
    inout egress_headers_t                         hdr,
    in    egress_metadata_t                        meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
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
    apply {
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
) cmac_1pipe_test;

Switch(cmac_1pipe_test) main;
