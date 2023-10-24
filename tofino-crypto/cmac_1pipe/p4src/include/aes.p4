// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef INCLUDE_AES_P4_GUARD
#define INCLUDE_AES_P4_GUARD

#define USE_HASH_ACTION_TABLES

#ifdef USE_HASH_ACTION_TABLES
    #define DEFAULT_ACTION(x) default_action = x;
#else
    #define DEFAULT_ACTION(x)
#endif

////////////
// Macros //
////////////

/** Key Tables **/

// Actions for key tables
#define add_key(B) add_key_b ## B

#define def_add_key(B, STATE) \
    action add_key(B)(bit<32> c0, bit<32> c1, bit<32> c2, bit<32> c3) { \
        STATE ## .c0 = STATE ## .c0 ^ c0; \
        STATE ## .c1 = STATE ## .c1 ^ c1; \
        STATE ## .c2 = STATE ## .c2 ^ c2; \
        STATE ## .c3 = STATE ## .c3 ^ c3; \
    }

#define tab_bB_rR_key(B, R) \
    table tab_b ## B ## _r ## R ## _key { \
        key = { \
            hdr.meta.iter : exact; \
            key_b ## B    : exact; \
        } \
        actions = { add_key(B); } \
        DEFAULT_ACTION(add_key(B(0, 0, 0, 0))) \
        size = 32; \
    }

// Add (XOR) round key to state
#define ADD_ROUND_KEY(B, R) tab_b ## B ## _r ## R ##_key.apply()

/** T-Tables **/

// Actions for T-tables
#define set_col0(B) set_col0_b ## B
#define set_col1(B) set_col1_b ## B
#define set_col2(B) set_col2_b ## B
#define set_col3(B) set_col3_b ## B
#define add_col0(B) add_col0_b ## B
#define add_col1(B) add_col1_b ## B
#define add_col2(B) add_col2_b ## B
#define add_col3(B) add_col3_b ## B

#define def_set_col0(B) \
    action set_col0(B)(bit<32> value) { \
        col0_b ## B = value; \
    }

#define def_set_col1(B) \
    action set_col1(B)(bit<32> value) { \
        col1_b ## B = value; \
    }

#define def_set_col2(B) \
    action set_col2(B)(bit<32> value) { \
        col2_b ## B = value; \
    }

#define def_set_col3(B) \
    action set_col3(B)(bit<32> value) { \
        col3_b ## B = value; \
    }

#define def_add_col0(B) \
    action add_col0(B)(bit<32> value) { \
        col0_b ## B = col0_b ## B ^ value; \
    }

#define def_add_col1(B) \
    action add_col1(B)(bit<32> value) { \
        col1_b ## B = col1_b ## B ^ value; \
    }

#define def_add_col2(B) \
    action add_col2(B)(bit<32> value) { \
        col2_b ## B = col2_b ## B ^ value; \
    }

#define def_add_col3(B) \
    action add_col3(B)(bit<32> value) { \
        col3_b ## B = col3_b ## B ^ value; \
    }

// Table T0 for the first column
#define tab_bB_rR_t0_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t0_c0 { \
        key = { STATE ## .c0[31:24] : exact; } \
        actions = { set_col0(B); } \
        DEFAULT_ACTION(set_col0(B)(0)) \
        size = 256; \
    }

// Table T0 for the second column
#define tab_bB_rR_t0_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t0_c1 { \
        key = { STATE ## .c1[31:24] : exact; } \
        actions = { set_col1(B); } \
        DEFAULT_ACTION(set_col1(B)(0)) \
        size = 256; \
    }

// Table T0 for the third column
#define tab_bB_rR_t0_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t0_c2 { \
        key = { STATE ## .c2[31:24] : exact; } \
        actions = { set_col2(B); } \
        DEFAULT_ACTION(set_col2(B)(0)) \
        size = 256; \
    }

// Table T0 for the fourth column
#define tab_bB_rR_t0_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t0_c3 { \
        key = { STATE ## .c3[31:24] : exact; } \
        actions = { set_col3(B); } \
        DEFAULT_ACTION(set_col3(B)(0)) \
        size = 256; \
    }

// Table T1 for the first column
#define tab_bB_rR_t1_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t1_c0 { \
        key = { STATE ## .c1[23:16] : exact; } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 256; \
    }

// Table T1 for the second column
#define tab_bB_rR_t1_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t1_c1 { \
        key = { STATE ## .c2[23:16] : exact; } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 256; \
    }

// Table T1 for the third column
#define tab_bB_rR_t1_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t1_c2 { \
        key = { STATE ## .c3[23:16] : exact; } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 256; \
    }

// Table T1 for the fourth column
#define tab_bB_rR_t1_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t1_c3 { \
        key = { STATE ## .c0[23:16] : exact; } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 256; \
    }

// Table T2 for the first column
#define tab_bB_rR_t2_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t2_c0 { \
        key = { STATE ## .c2[15:8] : exact; } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 256; \
    }

// Table T2 for the second column
#define tab_bB_rR_t2_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t2_c1 { \
        key = { STATE ## .c3[15:8] : exact; } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 256; \
    }

// Table T2 for the third column
#define tab_bB_rR_t2_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t2_c2 { \
        key = { STATE ## .c0[15:8] : exact; } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 256; \
    }

// Table T2 for the fourth column
#define tab_bB_rR_t2_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t2_c3 { \
        key = { STATE ## .c1[15:8] : exact; } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 256; \
    }

// Table T3 for the first column
#define tab_bB_rR_t3_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t3_c0 { \
        key = { STATE ## .c3[7:0] : exact; } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 256; \
    }

// Table T3 for the second column
#define tab_bB_rR_t3_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t3_c1 { \
        key = { STATE ## .c0[7:0] : exact; } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 256; \
    }

// Table T3 for the third column
#define tab_bB_rR_t3_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t3_c2 { \
        key = { STATE ## .c1[7:0] : exact; } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 256; \
    }

// Table T3 for the fourth column
#define tab_bB_rR_t3_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _t3_c3 { \
        key = { STATE ## .c2[7:0] : exact; } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 256; \
    }

// Declare T-tables for block B and round R. state is the aes_block_h header
// containing the state matrix to work on.
#define T_TABLES(B, R, STATE) \
    tab_bB_rR_t0_c0(B, R, STATE) \
    tab_bB_rR_t0_c1(B, R, STATE) \
    tab_bB_rR_t0_c2(B, R, STATE) \
    tab_bB_rR_t0_c3(B, R, STATE) \
    tab_bB_rR_t1_c0(B, R, STATE) \
    tab_bB_rR_t1_c1(B, R, STATE) \
    tab_bB_rR_t1_c2(B, R, STATE) \
    tab_bB_rR_t1_c3(B, R, STATE) \
    tab_bB_rR_t2_c0(B, R, STATE) \
    tab_bB_rR_t2_c1(B, R, STATE) \
    tab_bB_rR_t2_c2(B, R, STATE) \
    tab_bB_rR_t2_c3(B, R, STATE) \
    tab_bB_rR_t3_c0(B, R, STATE) \
    tab_bB_rR_t3_c1(B, R, STATE) \
    tab_bB_rR_t3_c2(B, R, STATE) \
    tab_bB_rR_t3_c3(B, R, STATE) \

// Apply T-tables to state for block B and round R.
#define APPLY_T_TABLES(B, R, STATE) \
    tab_b ## B ## _r ## R ## _t0_c0.apply(); \
    tab_b ## B ## _r ## R ## _t0_c1.apply(); \
    tab_b ## B ## _r ## R ## _t0_c2.apply(); \
    tab_b ## B ## _r ## R ## _t0_c3.apply(); \
    tab_b ## B ## _r ## R ## _t1_c0.apply(); \
    tab_b ## B ## _r ## R ## _t1_c1.apply(); \
    tab_b ## B ## _r ## R ## _t1_c2.apply(); \
    tab_b ## B ## _r ## R ## _t1_c3.apply(); \
    tab_b ## B ## _r ## R ## _t2_c0.apply(); \
    tab_b ## B ## _r ## R ## _t2_c1.apply(); \
    tab_b ## B ## _r ## R ## _t2_c2.apply(); \
    tab_b ## B ## _r ## R ## _t2_c3.apply(); \
    tab_b ## B ## _r ## R ## _t3_c0.apply(); \
    tab_b ## B ## _r ## R ## _t3_c1.apply(); \
    tab_b ## B ## _r ## R ## _t3_c2.apply(); \
    tab_b ## B ## _r ## R ## _t3_c3.apply(); \
    STATE ## .c0 = col0_b ## B; \
    STATE ## .c1 = col1_b ## B; \
    STATE ## .c2 = col2_b ## B; \
    STATE ## .c3 = col3_b ## B

/** S/T-Tables for Round 4 and 10 **/
// The last round of does not use the mix columns transformation.
// These tables match on an extra key bit to distinguish the 5th and the 10th
// round. For the 10th round they contain the S-Box bytes padded to 32 bit and
// shifted to the left by 3 (S0), 2 (S1), 1 (S2), and 0 (S3) bytes.
// We use the same actions as the regular T-tables for accumulating the columns
// vectors.

// Table S/T0 for the first column
#define tab_bB_rR_st0_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st0_c0 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c0[31:24] : exact; \
        } \
        actions = { set_col0(B); } \
        DEFAULT_ACTION(set_col0(B)(0)) \
        size = 512; \
    }

// Table S/T0 for the second column
#define tab_bB_rR_st0_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st0_c1 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c1[31:24] : exact; \
        } \
        actions = { set_col1(B); } \
        DEFAULT_ACTION(set_col1(B)(0)) \
        size = 512; \
    }

// Table S/T0 for the third column
#define tab_bB_rR_st0_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st0_c2 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c2[31:24] : exact; \
        } \
        actions = { set_col2(B); } \
        DEFAULT_ACTION(set_col2(B)(0)) \
        size = 512; \
    }

// Table S/T0 for the fourth column
#define tab_bB_rR_st0_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st0_c3 { \
        key = { \
            hdr.meta.iter  : exact; \
            STATE ## .c3[31:24] : exact;  \
        } \
        actions = { set_col3(B); } \
        DEFAULT_ACTION(set_col3(B)(0)) \
        size = 512; \
    }

// Table S/T1 for the first column
#define tab_bB_rR_st1_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st1_c0 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c1[23:16] : exact; \
        } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 512; \
    }

// Table S/T1 for the second column
#define tab_bB_rR_st1_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st1_c1 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c2[23:16] : exact; \
        } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 512; \
    }

// Table S/T1 for the third column
#define tab_bB_rR_st1_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st1_c2 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c3[23:16] : exact; \
        } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 512; \
    }

// Table S/T1 for the fourth column
#define tab_bB_rR_st1_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st1_c3 { \
        key = { \
            hdr.meta.iter       : exact; \
            STATE ## .c0[23:16] : exact; \
        } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 512; \
    }

// Table S/T2 for the first column
#define tab_bB_rR_st2_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st2_c0 { \
        key = { \
            hdr.meta.iter      : exact; \
            STATE ## .c2[15:8] : exact; \
        } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 512; \
    }

// Table S/T2 for the second column
#define tab_bB_rR_st2_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st2_c1 { \
        key = { \
            hdr.meta.iter      : exact; \
            STATE ## .c3[15:8] : exact; \
        } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 512; \
    }

// Table S/T2 for the third column
#define tab_bB_rR_st2_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st2_c2 { \
        key = { \
            hdr.meta.iter      : exact; \
            STATE ## .c0[15:8] : exact; \
        } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 512; \
    }

// Table S/T2 for the fourth column
#define tab_bB_rR_st2_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st2_c3 { \
        key = { \
            hdr.meta.iter      : exact; \
            STATE ## .c1[15:8] : exact; \
        } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 512; \
    }

// Table S/T3 for the first column
#define tab_bB_rR_st3_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st3_c0 { \
        key = { \
            hdr.meta.iter     : exact; \
            STATE ## .c3[7:0] : exact; \
        } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 512; \
    }

// Table S/T3 for the second column
#define tab_bB_rR_st3_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st3_c1 { \
        key = { \
            hdr.meta.iter     : exact; \
            STATE ## .c0[7:0] : exact; \
        } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 512; \
    }

// Table S/T3 for the third column
#define tab_bB_rR_st3_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st3_c2 { \
        key = { \
            hdr.meta.iter     : exact; \
            STATE ## .c1[7:0] : exact; \
        } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 512; \
    }

// Table S/T3 for the fourth column
#define tab_bB_rR_st3_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _st3_c3 { \
        key = { \
            hdr.meta.iter     : exact; \
            STATE ## .c2[7:0] : exact; \
        } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 512; \
    }

// Declare S/T-tables for block B and round R. state is the aes_block_h header
// containing the state matrix to work on.
#define ST_TABLES(B, R, STATE) \
    tab_bB_rR_st0_c0(B, R, STATE) \
    tab_bB_rR_st0_c1(B, R, STATE) \
    tab_bB_rR_st0_c2(B, R, STATE) \
    tab_bB_rR_st0_c3(B, R, STATE) \
    tab_bB_rR_st1_c0(B, R, STATE) \
    tab_bB_rR_st1_c1(B, R, STATE) \
    tab_bB_rR_st1_c2(B, R, STATE) \
    tab_bB_rR_st1_c3(B, R, STATE) \
    tab_bB_rR_st2_c0(B, R, STATE) \
    tab_bB_rR_st2_c1(B, R, STATE) \
    tab_bB_rR_st2_c2(B, R, STATE) \
    tab_bB_rR_st2_c3(B, R, STATE) \
    tab_bB_rR_st3_c0(B, R, STATE) \
    tab_bB_rR_st3_c1(B, R, STATE) \
    tab_bB_rR_st3_c2(B, R, STATE) \
    tab_bB_rR_st3_c3(B, R, STATE) \

// Apply S-tables to state for block B and round R.
#define APPLY_ST_TABLES(B, R, STATE) \
    tab_b ## B ## _r ## R ## _st0_c0.apply(); \
    tab_b ## B ## _r ## R ## _st0_c1.apply(); \
    tab_b ## B ## _r ## R ## _st0_c2.apply(); \
    tab_b ## B ## _r ## R ## _st0_c3.apply(); \
    tab_b ## B ## _r ## R ## _st1_c0.apply(); \
    tab_b ## B ## _r ## R ## _st1_c1.apply(); \
    tab_b ## B ## _r ## R ## _st1_c2.apply(); \
    tab_b ## B ## _r ## R ## _st1_c3.apply(); \
    tab_b ## B ## _r ## R ## _st2_c0.apply(); \
    tab_b ## B ## _r ## R ## _st2_c1.apply(); \
    tab_b ## B ## _r ## R ## _st2_c2.apply(); \
    tab_b ## B ## _r ## R ## _st2_c3.apply(); \
    tab_b ## B ## _r ## R ## _st3_c0.apply(); \
    tab_b ## B ## _r ## R ## _st3_c1.apply(); \
    tab_b ## B ## _r ## R ## _st3_c2.apply(); \
    tab_b ## B ## _r ## R ## _st3_c3.apply(); \
    STATE ## .c0 = col0_b ## B; \
    STATE ## .c1 = col1_b ## B; \
    STATE ## .c2 = col2_b ## B; \
    STATE ## .c3 = col3_b ## B

#endif // INCLUDE_AES_P4_GUARD
