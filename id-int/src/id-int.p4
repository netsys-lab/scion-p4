#include <core.p4>
#include <tna.p4>

#include "common_headers.p4"
#include "scion/parser.p4"
#include "scion/ingress.p4"
#include "idint/parser.p4"
#include "idint/ingress.p4"
#include "idint/egress.p4"


////////////////////////
// Ingress Processing //
////////////////////////

/** Headers **/

struct int_ingress_headers_t {
    idint_bridge_if_t    idint_bridge; // internal header
    ethernet_h           ethernet;
    sc_bridge_t          sc_bridge;
    ipv4_h               ipv4;
    ipv6_h               ipv6;
    udp_h                udp;
    sc_headers_t         scion;
    idint_ig_headers_t   idint;
}

/** Metadata **/

struct int_ingress_metadata_t {
    sc_meta_t scion;
}

/** Ingress Parser **/

parser IntIgParser(packet_in         pkt,
    out int_ingress_headers_t        hdr,
    out int_ingress_metadata_t       meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    ScionBrDiscardParser() sc_br_parser;
    ScionParser() scion_parser;
    IdIntParser() idint_parser;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition ethernet;
    }

    state ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etype) {
            ether_type_t.IPV4  : ipv4;
            ether_type_t.IPV6  : ipv6;
            ether_type_t.BRIDGE: bridge;
        }
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);
        transition udp_scion;
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);
        transition udp_scion;
    }

    state bridge {
        sc_br_parser.apply(pkt, hdr.sc_bridge.meta);
        transition udp_scion;
    }

    state udp_scion {
        pkt.extract(hdr.udp);
        scion_parser.apply(pkt, hdr.scion, hdr.sc_bridge, meta.scion);
        transition select (hdr.scion.common.next_hdr) {
            sc_proto_t.ID_INT: idint;
            default          : accept;
        }
    }

    state idint {
        idint_parser.apply(pkt, hdr.idint);
        transition accept;
    }
}

/** Ingress Deparser **/

control IntIgDeparser(packet_out                    pkt,
    inout int_ingress_headers_t                     hdr,
    in    int_ingress_metadata_t                    meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.idint_bridge);
        pkt.emit(hdr.sc_bridge);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.scion);
        pkt.emit(hdr.idint);
    }
}

/** Ingress Match-Action **/

control IntIngress(
    inout int_ingress_headers_t                     hdr,
    inout int_ingress_metadata_t                    meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    FirstPassScionIngress() scion_first_pass;
    SecondPassScionIngress() scion_second_pass;
    IdIntIngress() id_int_ingress;
    apply {
        bit pass;
        if (!hdr.sc_bridge.meta.isValid()) {
            // First pass
            pass = 0;
            scion_first_pass.apply(
                hdr.ipv4, hdr.ipv6, hdr.udp, hdr.scion,
                hdr.sc_bridge, meta.scion, ig_intr_md, ig_tm_md
            );

            // TODO: Decide to which "accelerator port" the packet should go to
            ig_tm_md.ucast_egress_port = 1;

        } else {
            // Second pass
            pass = 1;
            scion_second_pass.apply(hdr.scion, hdr.sc_bridge, meta.scion, ig_intr_md, ig_tm_md);
        }

        id_int_ingress.apply(hdr.idint, hdr.idint_bridge, pass, hdr.scion, meta.scion, ig_intr_md);
        if (!hdr.idint_bridge.hdr.isValid()) {
            // No need for egress processing if no new metadata has to be inserted
            ig_tm_md.bypass_egress = 1;
        }
    }
}

///////////////////////
// Egress Processing //
///////////////////////

/** Headers **/

struct int_egress_headers_t {
    // REMOVE: int_header_h      internal;
    ethernet_h        ethernet;
    idint_bridge_eg_t idint_bridge;
}

/** Metadata **/

struct int_egress_metadata_t {
    idint_eg_metadata_t idint;
}

/** Egress Parser **/

parser IntEgParser(packet_in        pkt,
    out int_egress_headers_t        hdr,
    out int_egress_metadata_t       meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    IdIntBrParser() bridge_parser;

    state start {
        pkt.extract(eg_intr_md);
        int_header_h inthdr = pkt.lookahead<int_header_h>();
        transition select (inthdr.int_hdr_type) {
            header_type_t.BRIDGE   : idint_bridge;
            header_type_t.EG_MIRROR: idint_mirror;
            default                : accept;
        }
    }

    state idint_bridge {
        bridge_parser.apply(pkt, hdr.idint_bridge);
        transition accept;
    }

    state idint_mirror {
        transition accept;
    }
}

/** Egress Deparser **/

control IntEgDeparser(packet_out                   pkt,
    inout int_egress_headers_t                     hdr,
    in    int_egress_metadata_t                    meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    Mirror(EGR_PORT_MIRROR) eg_mirror;

    apply {
        if (eg_dprsr_md.mirror_type == EGR_PORT_MIRROR) {
            eg_mirror.emit<eg_mirror_h>(
                meta.idint.mirror_session,
                {
                    hdr.idint_bridge.ig_meta.int_hdr_type,
                    hdr.idint_bridge.ig_meta.int_hdr_info
                }
            );
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.idint_bridge.eg_meta);
        pkt.emit(hdr.idint_bridge.md_hdr);
        pkt.emit(hdr.idint_bridge.metadata);
        pkt.emit(hdr.idint_bridge.mac);
    }
}

/** Egress Match-Action **/

control IntEgress(
    inout int_egress_headers_t                        hdr,
    inout int_egress_metadata_t                       meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    IdIntEgress() idint_egress;
    // IdIntMirrorEgress mirror_egress;

    apply {
        // Create a new Ethernet header
        hdr.ethernet.setValid();
        hdr.ethernet.dst = 0xFFFFFFFFFFFF;
        hdr.ethernet.src = 0xFFFFFFFFFFFF;
        hdr.ethernet.etype = ether_type_t.BRIDGE;

        if (hdr.idint_bridge.ig_meta.isValid()) {
            // Write metadata to bridge header
            idint_egress.apply(hdr.idint_bridge, meta.idint, eg_intr_md, eg_dprsr_md);
        } else {
            // Egress mirrored copy
        }
    }
}

//////////////
// Pipeline //
//////////////

Pipeline(
    IntIgParser(),
    IntIngress(),
    IntIgDeparser(),
    IntEgParser(),
    IntEgress(),
    IntEgDeparser()
) pipe;

Switch(pipe) main;
