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

/** S-Tables for Key Expansion **/

// Actions for S-Tables
#define add_byte0(B) add_byte0_b ## B
#define add_byte1(B) add_byte1_b ## B
#define add_byte2(B) add_byte2_b ## B
#define add_byte3(B) add_byte3_b ## B

#define def_add_byte0(B, KEY) \
    action add_byte0(B)(bit<8> value) { \
        byte0_b ## B = KEY ## .c0[31:24] ^ value; \
    }

#define def_add_byte1(B, KEY) \
    action add_byte1(B)(bit<8> value) { \
        byte1_b ## B = KEY ## .c0[23:16] ^ value; \
    }

#define def_add_byte2(B, KEY) \
    action add_byte2(B)(bit<8> value) { \
        byte2_b ## B = KEY ## .c0[15:8] ^ value; \
    }

#define def_add_byte3(B, KEY) \
    action add_byte3(B)(bit<8> value) { \
        byte3_b ## B = KEY ## .c0[7:0] ^ value; \
    }

#define tab_bB_rR_sbox_rcon_byte0(B, R, KEY) \
    table tab_b ## B ## _r ## R ## _sbox_rcon_byte0 { \
        key = { KEY ## .c3[23:16] : exact; } \
        actions = { add_byte0(B); } \
        DEFAULT_ACTION(add_byte0(B)(0)) \
        size = 256; \
    }

#define tab_bB_rR_sbox_byte1(B, R, KEY) \
    table tab_b ## B ## _r ## R ## _sbox_byte1 { \
        key = { KEY ## .c3[15:8] : exact; } \
        actions = { add_byte1(B); } \
        DEFAULT_ACTION(add_byte1(B)(0)) \
        size = 256; \
    }

#define tab_bB_rR_sbox_byte2(B, R, KEY) \
    table tab_b ## B ## _r ## R ## _sbox_byte2 { \
        key = { KEY ## .c3[7:0] : exact; } \
        actions = { add_byte2(B); } \
        DEFAULT_ACTION(add_byte2(B)(0)) \
        size = 256; \
    }

#define tab_bB_rR_sbox_byte3(B, R, KEY) \
    table tab_b ## B ## _r ## R ## _sbox_byte3 { \
        key = { KEY ## .c3[31:24] : exact; } \
        actions = { add_byte3(B); } \
        DEFAULT_ACTION(add_byte3(B)(0)) \
        size = 256; \
    }

// Declare S-Tables for key expansion for block B in round R.
#define S_TABLES_KEY_EXP(B, R, KEY) \
    tab_bB_rR_sbox_rcon_byte0(B, R, KEY) \
    tab_bB_rR_sbox_byte1(B, R, KEY) \
    tab_bB_rR_sbox_byte2(B, R, KEY) \
    tab_bB_rR_sbox_byte3(B, R, KEY)

// Calculate next round key for block B, round R.
#define EXPAND_KEY(B, R, KEY) \
    tab_b ## B ## _r ## R ## _sbox_rcon_byte0.apply(); \
    tab_b ## B ## _r ## R ## _sbox_byte1.apply(); \
    tab_b ## B ## _r ## R ## _sbox_byte2.apply(); \
    tab_b ## B ## _r ## R ## _sbox_byte3.apply(); \
    @in_hash { KEY ## .c0 = byte0_b##B ++ byte1_b##B ++ byte2_b##B ++ byte3_b##B; } \
    KEY ## .c1 = KEY ## .c1 ^ KEY ## .c0; \
    KEY ## .c2 = KEY ## .c2 ^ KEY ## .c1; \
    KEY ## .c3 = KEY ## .c3 ^ KEY ## .c2;

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

/** S-Tables for Round 10 **/
// The last round of does not use the mix columns transformation.
// These tables contain the S-Box bytes padded to 32 bit and shifted to the left
// by 3 (S0), 2 (S1), 1 (S2), and 0 (S3) bytes.
// We use the same actions as the T-tables for accumulating the columns vectors.

// Table S0 for the first column
#define tab_bB_rR_s0_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s0_c0 { \
        key = { STATE ## .c0[31:24] : exact; } \
        actions = { set_col0(B); } \
        DEFAULT_ACTION(set_col0(B)(0)) \
        size = 256; \
    }

// Table S0 for the second column
#define tab_bB_rR_s0_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s0_c1 { \
        key = { STATE ## .c1[31:24] : exact; } \
        actions = { set_col1(B); } \
        DEFAULT_ACTION(set_col1(B)(0)) \
        size = 256; \
    }

// Table S0 for the third column
#define tab_bB_rR_s0_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s0_c2 { \
        key = { STATE ## .c2[31:24] : exact; } \
        actions = { set_col2(B); } \
        DEFAULT_ACTION(set_col2(B)(0)) \
        size = 256; \
    }

// Table S0 for the fourth column
#define tab_bB_rR_s0_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s0_c3 { \
        key = { STATE ## .c3[31:24] : exact; } \
        actions = { set_col3(B); } \
        DEFAULT_ACTION(set_col3(B)(0)) \
        size = 256; \
    }

// Table S1 for the first column
#define tab_bB_rR_s1_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s1_c0 { \
        key = { STATE ## .c1[23:16] : exact; } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 256; \
    }

// Table S1 for the second column
#define tab_bB_rR_s1_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s1_c1 { \
        key = { STATE ## .c2[23:16] : exact; } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 256; \
    }

// Table S1 for the third column
#define tab_bB_rR_s1_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s1_c2 { \
        key = { STATE ## .c3[23:16] : exact; } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 256; \
    }

// Table S1 for the fourth column
#define tab_bB_rR_s1_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s1_c3 { \
        key = { STATE ## .c0[23:16] : exact; } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 256; \
    }

// Table S2 for the first column
#define tab_bB_rR_s2_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s2_c0 { \
        key = { STATE ## .c2[15:8] : exact; } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 256; \
    }

// Table S2 for the second column
#define tab_bB_rR_s2_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s2_c1 { \
        key = { STATE ## .c3[15:8] : exact; } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 256; \
    }

// Table S2 for the third column
#define tab_bB_rR_s2_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s2_c2 { \
        key = { STATE ## .c0[15:8] : exact; } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 256; \
    }

// Table S2 for the fourth column
#define tab_bB_rR_s2_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s2_c3 { \
        key = { STATE ## .c1[15:8] : exact; } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 256; \
    }

// Table S3 for the first column
#define tab_bB_rR_s3_c0(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s3_c0 { \
        key = { STATE ## .c3[7:0] : exact; } \
        actions = { add_col0(B); } \
        DEFAULT_ACTION(add_col0(B)(0)) \
        size = 256; \
    }

// Table S3 for the second column
#define tab_bB_rR_s3_c1(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s3_c1 { \
        key = { STATE ## .c0[7:0] : exact; } \
        actions = { add_col1(B); } \
        DEFAULT_ACTION(add_col1(B)(0)) \
        size = 256; \
    }

// Table S3 for the third column
#define tab_bB_rR_s3_c2(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s3_c2 { \
        key = { STATE ## .c1[7:0] : exact; } \
        actions = { add_col2(B); } \
        DEFAULT_ACTION(add_col2(B)(0)) \
        size = 256; \
    }

// Table S3 for the fourth column
#define tab_bB_rR_s3_c3(B, R, STATE) \
    table tab_b ## B ## _r ## R ## _s3_c3 { \
        key = { STATE ## .c2[7:0] : exact; } \
        actions = { add_col3(B); } \
        DEFAULT_ACTION(add_col3(B)(0)) \
        size = 256; \
    }

// Declare S-tables for block B and round R. state is the aes_block_h header
// containing the state matrix to work on.
#define S_TABLES(B, R, STATE) \
    tab_bB_rR_s0_c0(B, R, STATE) \
    tab_bB_rR_s0_c1(B, R, STATE) \
    tab_bB_rR_s0_c2(B, R, STATE) \
    tab_bB_rR_s0_c3(B, R, STATE) \
    tab_bB_rR_s1_c0(B, R, STATE) \
    tab_bB_rR_s1_c1(B, R, STATE) \
    tab_bB_rR_s1_c2(B, R, STATE) \
    tab_bB_rR_s1_c3(B, R, STATE) \
    tab_bB_rR_s2_c0(B, R, STATE) \
    tab_bB_rR_s2_c1(B, R, STATE) \
    tab_bB_rR_s2_c2(B, R, STATE) \
    tab_bB_rR_s2_c3(B, R, STATE) \
    tab_bB_rR_s3_c0(B, R, STATE) \
    tab_bB_rR_s3_c1(B, R, STATE) \
    tab_bB_rR_s3_c2(B, R, STATE) \
    tab_bB_rR_s3_c3(B, R, STATE) \

// Apply S-tables to state for block B and round R.
#define APPLY_S_TABLES(B, R, STATE) \
    tab_b ## B ## _r ## R ## _s0_c0.apply(); \
    tab_b ## B ## _r ## R ## _s0_c1.apply(); \
    tab_b ## B ## _r ## R ## _s0_c2.apply(); \
    tab_b ## B ## _r ## R ## _s0_c3.apply(); \
    tab_b ## B ## _r ## R ## _s1_c0.apply(); \
    tab_b ## B ## _r ## R ## _s1_c1.apply(); \
    tab_b ## B ## _r ## R ## _s1_c2.apply(); \
    tab_b ## B ## _r ## R ## _s1_c3.apply(); \
    tab_b ## B ## _r ## R ## _s2_c0.apply(); \
    tab_b ## B ## _r ## R ## _s2_c1.apply(); \
    tab_b ## B ## _r ## R ## _s2_c2.apply(); \
    tab_b ## B ## _r ## R ## _s2_c3.apply(); \
    tab_b ## B ## _r ## R ## _s3_c0.apply(); \
    tab_b ## B ## _r ## R ## _s3_c1.apply(); \
    tab_b ## B ## _r ## R ## _s3_c2.apply(); \
    tab_b ## B ## _r ## R ## _s3_c3.apply(); \
    STATE ## .c0 = col0_b ## B; \
    STATE ## .c1 = col1_b ## B; \
    STATE ## .c2 = col2_b ## B; \
    STATE ## .c3 = col3_b ## B

/** Add round key **/

// Add (XOR) round key to state
#define ADD_ROUND_KEY(B, KEY) \
    hdr.block ## B ##.c0 = hdr.block ## B ##.c0 ^ KEY ## .c0; \
    hdr.block ## B ##.c1 = hdr.block ## B ##.c1 ^ KEY ## .c1; \
    hdr.block ## B ##.c2 = hdr.block ## B ##.c2 ^ KEY ## .c2; \
    hdr.block ## B ##.c3 = hdr.block ## B ##.c3 ^ KEY ## .c3

#endif // INCLUDE_AES_P4_GUARD
