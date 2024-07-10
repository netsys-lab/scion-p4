#ifndef IDINT_EGRESS_P4_GUARD
#define IDINT_EGRESS_P4_GUARD

#include <core.p4>
#include <tna.p4>

#include "headers.p4"
#include "instructions.p4"

// TODO: Set from control plane
#define MY_NODE_ID 1

#define MD_LEN_0 0x0
#define MD_LEN_2 0x4
#define MD_LEN_4 0x5
#define MD_LEN_6 0x6
#define MD_LEN_8 0x7

#define FIRST_PASS 0

struct idint_temp_md_t {
    bit<16> meta2;
    bit<32> meta4;
    bit<48> meta6;
    bit<64> meta8;
};

//////////////////
// LoadMetadata //
//////////////////

// Load metadata requested by `instruction` into output registers of the appropriate size.
control LoadMetadata(
    in  bit<8>                     instruction,
    out idint_temp_md_t            metadata,
    out bit<3>                     length,
    in idint_bridge_meta_ig_h      ig_bridged_md,
    in egress_intrinsic_metadata_t eg_intr_md)
{
    action empty() {
        length = MD_LEN_0;
    }

    action const2(bit<16> value) {
        length = MD_LEN_2;
        metadata.meta2 = value;
    }

    action const4(bit<32> value) {
        length = MD_LEN_4;
        metadata.meta4 = value;
    }

    action const6(bit<48> value) {
        length = MD_LEN_6;
        metadata.meta6 = value;
    }

    action const8(bit<64> value) {
        length = MD_LEN_8;
        metadata.meta8 = value;
    }

    action ingress_port() {
        length = MD_LEN_4;
        @in_hash {
            metadata.meta4 = (bit<32>)ig_bridged_md.ingress_port;
        }
    }

    action ingress_tstamp() {
        length = MD_LEN_6;
        metadata.meta6 = ig_bridged_md.ingress_tstamp;
    }

    action queue_id() {
        length = MD_LEN_4;
        metadata.meta4 = (bit<32>)eg_intr_md.egress_qid;
    }

    action queue_depth() {
        length = MD_LEN_4;
        metadata.meta4 = (bit<32>)eg_intr_md.enq_qdepth;
    }

    table ing_md_tab {
        key = {
            instruction : exact;
        }
        actions = {
            empty;
            const2; const4; const6; const8;
            ingress_port;
            ingress_tstamp;
            queue_id;
            queue_depth;
        }
        default_action = empty();
        size = 1024;
        const entries = {
            idint_mdid_t.UPTIME : const4(10000);
            idint_mdid_t.INGRESS_TSTAMP: ingress_tstamp();
            idint_mdid_t.QUEUE_ID : queue_id();
            idint_mdid_t.INST_QUEUE_LEN : queue_depth();
        }
    }

    apply {
        ing_md_tab.apply();
    }
}

//////////////
// AggrFunc //
//////////////

// Apply the aggregation function.
// The min, max and sum functions are currently not implemented for 6 byte operands.
control AggrFunc(
    in idint_af_t      aggr_func,
    inout idint_meta_t md,
    in idint_temp_md_t new_value,
    in bit<3>          length)
{
    action first2() {
        md.meta2.setValid();
        md.meta2.data = new_value.meta2;
    }

    action first4() {
        md.meta4.setValid();
        md.meta4.data = new_value.meta4;
    }

    action first6() {
        md.meta6.setValid();
        md.meta6.data = new_value.meta6;
    }

    action first8() {
        md.meta8.setValid();
        md.meta8.data = new_value.meta8;
    }

    action last() {
        // empty
    }

    action min2() {
        md.meta2.setValid();
        md.meta2.data = min(md.meta2.data, new_value.meta2);
    }

    action min4() {
        md.meta4.setValid();
        md.meta4.data = min(md.meta4.data, new_value.meta4);
    }

    action min8() {
        md.meta8.setValid();
        md.meta8.data = min(md.meta8.data, new_value.meta8);
    }

    action max2() {
        md.meta2.setValid();
        md.meta2.data = max(md.meta2.data, new_value.meta2);
    }

    action max4() {
        md.meta4.setValid();
        md.meta4.data = max(md.meta4.data, new_value.meta4);
    }

    action max8() {
        md.meta8.setValid();
        md.meta8.data = max(md.meta8.data, new_value.meta8);
    }

    action sum2() {
        md.meta2.setValid();
        md.meta2.data = md.meta2.data + new_value.meta2;
    }

    action sum4() {
        md.meta4.setValid();
        md.meta4.data = md.meta4.data + new_value.meta4;
    }

    action sum8() {
        md.meta8.setValid();
        md.meta8.data = md.meta8.data + new_value.meta8;
    }

    table aggr_tab {
        key = {
            aggr_func : exact;
            length    : exact;
        }
        actions = {
            first2; first4; first6; first8;
            last;
            min2; min4; min8;
            max2; max4; max8;
            sum2; sum4; sum8;
        }
        default_action = last();
        size = 32;
        const entries = {
            (idint_af_t.FIRST, MD_LEN_2) : first2();
            (idint_af_t.LAST,  MD_LEN_2) : last();
            (idint_af_t.MIN,   MD_LEN_2) : min2();
            (idint_af_t.MAX,   MD_LEN_2) : max2();
            (idint_af_t.SUM,   MD_LEN_2) : sum2();
            (idint_af_t.FIRST, MD_LEN_4) : first4();
            (idint_af_t.LAST,  MD_LEN_4) : last();
            (idint_af_t.MIN,   MD_LEN_4) : min4();
            (idint_af_t.MAX,   MD_LEN_4) : max4();
            (idint_af_t.SUM,   MD_LEN_4) : sum4();
            (idint_af_t.FIRST, MD_LEN_6) : first6();
            (idint_af_t.LAST,  MD_LEN_6) : last();
            (idint_af_t.FIRST, MD_LEN_8) : first8();
            (idint_af_t.LAST,  MD_LEN_8) : last();
            (idint_af_t.MIN,   MD_LEN_8) : min8();
            (idint_af_t.MAX,   MD_LEN_8) : max8();
            (idint_af_t.SUM,   MD_LEN_8) : sum8();
        }
    }

    apply {
        aggr_tab.apply();
    }
}

/////////////////
// IdIntEgress //
/////////////////

// Get the requested metadata, merge it with metadata from the previous hop if required, and prepare
// the bridge header for the external accelerator.
// On the second pass through egress, all bridge headers are removed and the packet is egress
// mirrored with select metadata prepended in the mirror header.
// This control is not called on an already mirrored copy of the packet, which should simply be
// forwarded to the accelerator or CPU.
control IdIntEgress(
    inout idint_bridge_eg_t                        hdr,
    out   idint_eg_metadata_t                      meta,
    in    egress_intrinsic_metadata_t              eg_intr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) identity_hash_16;

    LoadMetadata() load_md_1;
    LoadMetadata() load_md_2;
    LoadMetadata() load_md_3;
    LoadMetadata() load_md_4;

    AggrFunc() aggr_1;
    AggrFunc() aggr_2;
    AggrFunc() aggr_3;
    AggrFunc() aggr_4;

    // Local variables
    bit<8> hop_len;
    bit set_node_count = 0;
    bit set_node_id = 0;
    bit set_ingress_iface = 0;
    bit set_egress_iface = 0;
    bit<3> ml1;
    bit<3> ml2;
    bit<3> ml3;
    bit<3> ml4;
    idint_temp_md_t md1;
    idint_temp_md_t md2;
    idint_temp_md_t md3;
    idint_temp_md_t md4;

    // Prevent bridge headers from being emitted.
    action invalidate_bridge_headers() {
        hdr.eg_meta.setInvalid();
        hdr.md_hdr.setInvalid();
        hdr.metadata.node_count.setInvalid();
        hdr.metadata.node_id.setInvalid();
        hdr.metadata.ingress_iface.setInvalid();
        hdr.metadata.egress_iface.setInvalid();
        hdr.metadata.data1.meta2.setInvalid();
        hdr.metadata.data1.meta4.setInvalid();
        hdr.metadata.data1.meta6.setInvalid();
        hdr.metadata.data1.meta8.setInvalid();
        hdr.metadata.data2.meta2.setInvalid();
        hdr.metadata.data2.meta4.setInvalid();
        hdr.metadata.data2.meta6.setInvalid();
        hdr.metadata.data2.meta8.setInvalid();
        hdr.metadata.data3.meta2.setInvalid();
        hdr.metadata.data3.meta4.setInvalid();
        hdr.metadata.data3.meta6.setInvalid();
        hdr.metadata.data3.meta8.setInvalid();
        hdr.metadata.data4.meta2.setInvalid();
        hdr.metadata.data4.meta4.setInvalid();
        hdr.metadata.data4.meta6.setInvalid();
        hdr.metadata.data4.meta8.setInvalid();
        hdr.mac.setInvalid();
    }

    // Add length to hop_len metadata.
    action add_to_hdr_len(bit<8> length) {
        hop_len = hop_len + length;
    }

    // Add the length of the fixed metadata fields to the total stack entry length.
    table fixed_md_len {
        key = {
            set_node_count    : exact;
            set_node_id       : exact;
            set_ingress_iface : exact;
            set_egress_iface  : exact;
        }
        actions = { add_to_hdr_len; }
        default_action = add_to_hdr_len(0);
        size = 16; // 2^4
    }

    // Add the length of the variable metadata to the total stack entry length.
    table var_md_len {
        key = {
            ml1           : exact;
            ml2           : exact;
            ml3           : exact;
            ml4           : exact;
        }
        actions = { add_to_hdr_len; }
        default_action = add_to_hdr_len(0);
        size = 625; // 5^4
    }

    apply {
        // Check header validity
        if (!(hdr.ig_meta.isValid() && hdr.md_hdr.isValid())) {
            return;
        }

        // Load variable-length metadata
        load_md_1.apply(hdr.ig_meta.inst1, md1, ml1, hdr.ig_meta, eg_intr_md);
        load_md_2.apply(hdr.ig_meta.inst2, md2, ml2, hdr.ig_meta, eg_intr_md);
        load_md_3.apply(hdr.ig_meta.inst3, md3, ml3, hdr.ig_meta, eg_intr_md);
        load_md_4.apply(hdr.ig_meta.inst4, md4, ml4, hdr.ig_meta, eg_intr_md);

        // Aggregate variable-length metadata
        if (hdr.ig_meta.merge == 0)
        {
            // If metadata is not merged simply copy the new values into the new header
            hdr.ig_meta.aggr_func_1 = idint_af_t.LAST;
            hdr.ig_meta.aggr_func_2 = idint_af_t.LAST;
            hdr.ig_meta.aggr_func_3 = idint_af_t.LAST;
            hdr.ig_meta.aggr_func_4 = idint_af_t.LAST;
        }
        aggr_1.apply(hdr.ig_meta.aggr_func_1, hdr.metadata.data1, md1, ml1);
        aggr_2.apply(hdr.ig_meta.aggr_func_2, hdr.metadata.data2, md2, ml2);
        aggr_3.apply(hdr.ig_meta.aggr_func_3, hdr.metadata.data3, md3, ml3);
        aggr_4.apply(hdr.ig_meta.aggr_func_4, hdr.metadata.data4, md4, ml4);

        // Fixed metadata
        if (hdr.ig_meta.node_count == 1) {
            set_node_count = 1;
            hdr.metadata.node_count.setValid();
            hdr.metadata.node_count.data = 0;
        }
        if (hdr.ig_meta.node_id == 1) {
            set_node_id = 1;
            hdr.metadata.node_id.setValid();
            hdr.metadata.node_id.data = MY_NODE_ID;
        }
        if (hdr.ig_meta.ingress_iface == 1) {
            set_ingress_iface = 1;
            hdr.metadata.ingress_iface.setValid();
            @in_hash {
                hdr.metadata.ingress_iface.data = (bit<32>)hdr.ig_meta.ingress_port;
            }
        }
        if (hdr.ig_meta.egress_iface == 1) {
            set_egress_iface = 1;
            hdr.metadata.egress_iface.setValid();
            @in_hash {
                hdr.metadata.egress_iface.data = (bit<32>)eg_intr_md.egress_port;
            }
        }

        // Set metadata presence bits
        hdr.md_hdr.flags_and_meta_len = identity_hash_16.get({
            set_node_count, set_node_id, set_ingress_iface, set_egress_iface,
            ml1, ml2, ml3, ml4
        });

        if (hdr.ig_meta.int_hdr_info == FIRST_PASS) {
            // Initialize egress bridge header
            hdr.eg_meta.setValid();
            hdr.eg_meta.mac = 1;
            hdr.eg_meta.encrypt = 0;
            hdr.eg_meta.hop_offset = 0; // TODO
            hop_len = (bit<8>)(sizeInBytes(hdr.md_hdr) + sizeInBytes(hdr.mac));
            fixed_md_len.apply();
            var_md_len.apply();
            hdr.eg_meta.hop_len = hop_len;
        } else {
            // Enable egress mirror
            eg_dprsr_md.mirror_type = EGR_PORT_MIRROR;
            hdr.ig_meta.int_hdr_type = header_type_t.EG_MIRROR;
            hdr.ig_meta.int_hdr_info = 0;
            meta.mirror_session = 1; // TODO: Get from table
            invalidate_bridge_headers();
        }
    }
}

#endif // IDINT_EGRESS_P4_GUARD
