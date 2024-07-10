#ifndef IDINT_INGRESS_P4_GUARD
#define IDINT_INGRESS_P4_GUARD

#include <core.p4>
#include <tna.p4>

#include "headers.p4"
#include "../scion/headers.p4"
#include "instructions.p4"

const int IDINT_VERIF_IPV4_TABLE_SIZE = 4096;
const int IDINT_VERIF_IPV6_TABLE_SIZE = 4096;

//////////////////
// IdIntIngress //
//////////////////

// Determine whether metadata is appended or merged, initialize the bridge header and copy metadata
// fields from previous hop for egress.
control IdIntIngress(
    inout idint_ig_headers_t           idint,
    out   idint_bridge_if_t            bridge,
    in    bit                          pass,
    in    sc_headers_t                 scion,
    in    sc_meta_t                    meta,
    in    ingress_intrinsic_metadata_t ig_intr_md)
{
    // Local variables
#if 0
    bit<16>  verif_isd;
    bit<48>  verif_asn;
    bit<32>  verif_host_ipv4;
    bit<128> verif_host_ipv6;
#endif

    // Append a new entry to the telemetry stack.
    action append(bit ingress, bit egress, bit aggregate) {
        bridge.hdr.merge          = 0;
        bridge.hdr.source         = 0;
        bridge.hdr.ingress        = ingress;
        bridge.hdr.egress         = egress;
        bridge.hdr.aggregate      = aggregate;
        bridge.hdr.encrypted      = 0;
        bridge.hdr.reserved_flags = 0;
        bridge.hdr.reserved       = 0;
    }

    // Merge telemetry data with current topmost stack entry.
    action merge(bit egress) {
        bridge.hdr.merge          = 1;
        bridge.hdr.source         = idint.md_hdr.source;
        bridge.hdr.ingress        = idint.md_hdr.ingress;
        bridge.hdr.egress         = egress;
        bridge.hdr.aggregate      = 1;
        bridge.hdr.encrypted      = idint.md_hdr.encrypted;
        bridge.hdr.reserved_flags = idint.md_hdr.reserved_flags;
        bridge.hdr.reserved       = idint.md_hdr.reserved;
    }

    table telemetry_mode {
        key = {
            idint.md_hdr.source           : ternary;
            idint.md_hdr.ingress          : ternary;
            idint.hdr.mode_and_verif[1:0] : ternary;
            meta.as_ingress               : ternary;
            meta.as_egress                : ternary;
        }
        actions = { append; merge; NoAction; }
        default_action = NoAction();
        size = 32;
        const entries = {
            // Previous hop was INT source
            (1, _, _, 1, 0) : append(1, 0, 0); // AS ingress
            (1, _, _, 1, 1) : append(1, 1, 0); // AS ingress and egress
            (1, _, _, 0, 0) : append(0, 0, 0); // Transit hop
            (1, _, _, 0, 1) : append(0, 1, 0); // AS egress
            // Mode 0 (always append)
            (0, _, 0, 1, 0) : append(1, 0, 0); // AS ingress
            (0, _, 0, 1, 1) : append(1, 1, 0); // AS ingress and egress
            (0, _, 0, 0, 0) : append(0, 0, 0); // Transit hop
            (0, _, 0, 0, 1) : append(0, 1, 0); // AS egress
            // Mode 1
            (0, _, 1, 1, _) : append(1, 0, 0); // AS ingress
            (0, _, 1, 0, 0) :  merge(   0   ); // Transit hop
            (0, _, 1, 0, 1) :  merge(   1   ); // AS egress
            // Mode 2
            (0, 0, 2, 1, 0) : append(1, 0, 0); // AS ingress
            (0, 0, 2, 1, 1) : append(1, 1, 1); // AS ingress and egress
            (0, 1, 2, 0, 0) : append(0, 0, 0); // First transit hop
            (0, 0, 2, 0, 0) :  merge(   0   ); // Transit hop
            (0, _, 2, 0, 1) : append(0, 1, 0); // AS egress
            // Mode 3
            (0, 0, 3, 1, 0) : append(1, 0, 0); // AS ingress
            (0, 0, 3, 1, 1) : append(1, 1, 1); // AS ingress and egress set
            (0, 1, 3, 0, 0) : append(0, 0, 0); // First transit hop
            (0, 0, 3, 0, 0) :  merge(   0   ); // Transit hop
            (0, _, 3, 0, 1) : append(0, 1, 0); // AS egress
        }
    }

    action set_verif_key_id(bit<32> id) {
        bridge.key.key_id = id;
    }

#if 0
    table verifier_ipv4 {
        key = {
            verif_isd       : exact;
            verif_asn       : exact;
            verif_host_ipv4 : exact;
        }
        actions = { set_verif_key_id; }
        default_action = set_verif_key_id(0);
        size = IDINT_VERIF_IPV4_TABLE_SIZE;
    }

    table verifier_ipv6 {
        key = {
            verif_isd       : exact;
            verif_asn       : exact;
            verif_host_ipv6 : exact;
        }
        actions = { set_verif_key_id; }
        default_action = set_verif_key_id(0);
        size = IDINT_VERIF_IPV6_TABLE_SIZE;
    }
#endif

    apply {
        if (!(idint.hdr.isValid() && idint.md_hdr.isValid())) {
            return;
        }

        // TODO: Update stack length on second pass

        // Check delay hops
        if (idint.hdr.delay_hops > 0) {
            idint.hdr.delay_hops = idint.hdr.delay_hops - 1;
            return;
        }

        // Initialize bridge header
        bridge.hdr.setValid();
        bridge.hdr.int_hdr_type = header_type_t.BRIDGE;
        bridge.hdr.int_hdr_info = (bit<4>)pass;
        @in_hash {
            bridge.hdr.ingress_port = (bit<15>)ig_intr_md.ingress_port;
        }
        bridge.hdr.ingress_tstamp = ig_intr_md.ingress_mac_tstamp;

        // Copy instructions to bridge header
        bridge.hdr.node_count = idint.hdr.node_count;
        bridge.hdr.node_id = idint.hdr.node_id;
        bridge.hdr.ingress_iface = idint.hdr.ingress_iface;
        bridge.hdr.egress_iface = idint.hdr.egress_iface;
        bridge.hdr.aggr_func_1 = idint.hdr.aggr_func_1;
        bridge.hdr.aggr_func_2 = idint.hdr.aggr_func_2;
        bridge.hdr.aggr_func_3 = idint.hdr.aggr_func_3;
        bridge.hdr.aggr_func_4 = idint.hdr.aggr_func_4;
        bridge.hdr.inst1 = idint.hdr.inst1;
        bridge.hdr.inst2 = idint.hdr.inst2;
        bridge.hdr.inst3 = idint.hdr.inst3;
        bridge.hdr.inst4 = idint.hdr.inst4;

        // Initialize metadata header either for appending as a new hop entry or for merging with
        // the metadata currently at the top of the stack.
        telemetry_mode.apply();
        if (bridge.hdr.merge == 0) {
            // Check and update remaining hop count
            if (idint.hdr.rem_hops > 0) {
                idint.hdr.rem_hops = idint.hdr.rem_hops - 1;
            } else {
                idint.hdr.hop_count_exceeded = 1;
                bridge.hdr.setInvalid();
                return;
            }
        }
        bridge.hdr.flags_and_meta_len = idint.md_hdr.flags_and_meta_len;

        // Copy metadata to bridge header
        bridge.node_count = idint.metadata.node_count;
        bridge.node_id = idint.metadata.node_id;
        bridge.ingress_iface = idint.metadata.ingress_iface;
        bridge.egress_iface = idint.metadata.egress_iface;
        if (idint.metadata.data1.meta2.isValid()) {
            bridge.data1.setValid();
            bridge.data1.data = (bit<64>)idint.metadata.data1.meta2.data;
        } else if (idint.metadata.data1.meta4.isValid()) {
            bridge.data1.setValid();
            bridge.data1.data = (bit<64>)idint.metadata.data1.meta4.data;
        } else if (idint.metadata.data1.meta6.isValid()) {
            bridge.data1.setValid();
            bridge.data1.data = (bit<64>)idint.metadata.data1.meta6.data;
        } else if (idint.metadata.data1.meta8.isValid()) {
            bridge.data1.setValid();
            bridge.data1.data = idint.metadata.data1.meta8.data;
        }
        if (idint.metadata.data2.meta2.isValid()) {
            bridge.data2.setValid();
            bridge.data2.data = (bit<64>)idint.metadata.data2.meta2.data;
        } else if (idint.metadata.data2.meta4.isValid()) {
            bridge.data2.setValid();
            bridge.data2.data = (bit<64>)idint.metadata.data2.meta4.data;
        } else if (idint.metadata.data2.meta6.isValid()) {
            bridge.data2.setValid();
            bridge.data2.data = (bit<64>)idint.metadata.data2.meta6.data;
        } else if (idint.metadata.data2.meta8.isValid()) {
            bridge.data2.setValid();
            bridge.data2.data = idint.metadata.data2.meta8.data;
        }
        if (idint.metadata.data3.meta2.isValid()) {
            bridge.data3.setValid();
            bridge.data3.data = (bit<64>)idint.metadata.data3.meta2.data;
        } else if (idint.metadata.data3.meta4.isValid()) {
            bridge.data3.setValid();
            bridge.data3.data = (bit<64>)idint.metadata.data3.meta4.data;
        } else if (idint.metadata.data3.meta6.isValid()) {
            bridge.data3.setValid();
            bridge.data3.data = (bit<64>)idint.metadata.data3.meta6.data;
        } else if (idint.metadata.data3.meta8.isValid()) {
            bridge.data3.setValid();
            bridge.data3.data = idint.metadata.data3.meta8.data;
        }
        if (idint.metadata.data4.meta2.isValid()) {
            bridge.data4.setValid();
            bridge.data4.data = (bit<64>)idint.metadata.data4.meta2.data;
        } else if (idint.metadata.data4.meta4.isValid()) {
            bridge.data4.setValid();
            bridge.data4.data = (bit<64>)idint.metadata.data4.meta4.data;
        } else if (idint.metadata.data4.meta6.isValid()) {
            bridge.data4.setValid();
            bridge.data4.data = (bit<64>)idint.metadata.data4.meta6.data;
        } else if (idint.metadata.data4.meta8.isValid()) {
            bridge.data4.setValid();
            bridge.data4.data = idint.metadata.data4.meta8.data;
        }

        // Copy MAC for MAC chaining
        if (idint.mac.isValid()) {
            bridge.hdr.mac = idint.mac.mac;
        }

        // Find AES key index for MAC and encryption
        bridge.key.setValid();
        bridge.key.key_id = 0;
#if 0
        if (idint.hdr.mode_and_verif[3:2] == idint_verif_t.THIRD_PARTY) {
            if (idint.hdr.mode_and_verif[7:6] == 0) {
                verifier_third_party_ipv4.apply();
            } else if (idint.hdr.mode_and_verif[7:6] == 3) {
                verifier_third_party_ipv6.apply();
            }
        } else if (idint.hdr.mode_and_verif[3:2] == idint_verif_t.DESTINATION) {
            if (scion.common.host_type_len[3:0] == 0x03) {
                verifier_destination_ipv4.apply();
            } else if (scion.common.host_type_len[3:0] == 0x0F) {
                verifier_destination_ipv6.apply();
            }
        } else if (idint.hdr.mode_and_verif[3:2] == idint_verif_t.SOURCE) {
            if (scion.common.host_type_len[7:4] == 0x03) {
                verifier_source_ipv4.apply();
            } else if (scion.common.host_type_len[7:4] == 0x0F) {
                verifier_source_ipv6.apply();
            }
        }
#endif
    }
}

#endif // IDINT_INGRESS_P4_GUARD
