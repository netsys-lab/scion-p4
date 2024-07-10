#ifndef SCION_INGRESS_P4_GUARD
#define SCION_INGRESS_P4_GUARD

#include <core.p4>
#include <tna.p4>

#include "headers.p4"
#include "../common_headers.p4"

///////////////////////////
// FirstPassScionIngress //
///////////////////////////

// SCION ingress processing on the first pass
control FirstPassScionIngress(
    inout ipv4_h                              ipv4,
    inout ipv6_h                              ipv6,
    inout udp_h                               udp,
    inout sc_headers_t                        scion,
    out   sc_bridge_t                         bridge,
    inout sc_meta_t                           meta,
    in    ingress_intrinsic_metadata_t        ig_intr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    action set_ipv4(bit<32> src, bit<32> dst, bit<16> udp_src, bit<16> udp_dst) {
        ipv6.setInvalid();
        ipv4.setValid();
        ipv4.src = src;
        ipv4.dst = dst;
        udp.src = udp_src;
        udp.dst = udp_dst;
    }

    table forward_ipv4 {
        key = {
            bridge.meta.egress_port : exact;
        }
        actions = { set_ipv4; NoAction; }
        default_action = NoAction();
        size = 128;
    }

    apply {
        bridge.meta.setValid();
        bridge.meta.egress_port = 1; // TODO
        forward_ipv4.apply();

        meta.as_ingress = 0; // TODO
        meta.as_egress = 0; // TODO
        meta.curr_hf = 63;
        if (scion.path_meta.isValid()) {
            meta.curr_hf = scion.path_meta.curr_hf;
        }
    }
}

////////////////////////////
// SecondPassScionIngress //
////////////////////////////

// SCION ingress processing on the second pass
control SecondPassScionIngress(
    inout sc_headers_t                        scion,
    out   sc_bridge_t                         bridge,
    inout sc_meta_t                           meta,
    in    ingress_intrinsic_metadata_t        ig_intr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    apply {
        if (bridge.meta.first_hf_valid == 1) {
            ig_tm_md.ucast_egress_port = (PortId_t)bridge.meta.egress_port;
        }
        bridge.meta.setInvalid();
    }
}

#endif // SCION_INGRESS_P4_GUARD
