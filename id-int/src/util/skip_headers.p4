#ifndef UTIL_SKIP_HEADERS_P4_GUARD
#define UTIL_SKIP_HEADERS_P4_GUARD

header skip4_h {
    bit<(4*8)> data;
}

header skip8_h {
    bit<(8*8)> data;
}

header skip12_h {
    bit<(12*8)> data;
}

header skip16_h {
    bit<(16*8)> data;
}

header skip20_h {
    bit<(20*8)> data;
}

header skip24_h {
    bit<(24*8)> data;
}

header skip28_h {
    bit<(28*8)> data;
}

header skip32_h {
    bit<(32*8)> data;
}

header skip36_h {
    bit<(36*8)> data;
}

header skip40_h {
    bit<(40*8)> data;
}

header skip44_h {
    bit<(44*8)> data;
}

header skip48_h {
    bit<(48*8)> data;
}

header skip52_h {
    bit<(52*8)> data;
}

header skip56_h {
    bit<(56*8)> data;
}

header skip60_h {
    bit<(60*8)> data;
}

header skip64_h {
    bit<(64*8)> data;
}

struct skip_t {
    skip4_h skip4;
    skip8_h skip8;
    skip12_h skip12;
    skip16_h skip16;
    skip20_h skip20;
    skip24_h skip24;
    skip28_h skip28;
    skip32_h skip32;
    // skip36_h skip36;
    // skip40_h skip40;
    // skip44_h skip44;
    // skip48_h skip48;
    // skip52_h skip52;
    // skip56_h skip56;
    // skip60_h skip60;
    // skip64_h skip64;
}

#endif // UTIL_SKIP_HEADERS_P4_GUARD
