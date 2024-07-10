#ifndef UTIL_SKIP_PARSER_P4_GUARD
#define UTIL_SKIP_PARSER_P4_GUARD

#include "skip_headers.p4"

// `bytes` is the number of bytes to skip in multiples of 4 bytes.
parser SkipParser(packet_in pkt, out skip_t hdr, in bit<8> bytes)
{
    state start {
        transition select (bytes) {
             0: accept;
             1: skip4;
             2: skip8;
             3: skip12;
             4: skip16;
             5: skip20;
             6: skip24;
             7: skip28;
             8: skip32;
            //  9: skip36;
            // 10: skip40;
            // 11: skip44;
            // 12: skip48;
            // 13: skip52;
            // 14: skip56;
            // 15: skip60;
            // 16: skip64;
        }
    }

    state skip4 {
        pkt.extract(hdr.skip4);
        transition accept;
    }

    state skip8 {
        pkt.extract(hdr.skip8);
        transition accept;
    }

    state skip12 {
        pkt.extract(hdr.skip12);
        transition accept;
    }

    state skip16 {
        pkt.extract(hdr.skip16);
        transition accept;
    }

    state skip20 {
        pkt.extract(hdr.skip20);
        transition accept;
    }

    state skip24 {
        pkt.extract(hdr.skip24);
        transition accept;
    }

    state skip28 {
        pkt.extract(hdr.skip28);
        transition accept;
    }

    state skip32 {
        pkt.extract(hdr.skip32);
        transition accept;
    }

    // state skip36 {
    //     pkt.extract(hdr.skip36);
    //     transition accept;
    // }

    // state skip40 {
    //     pkt.extract(hdr.skip40);
    //     transition accept;
    // }

    // state skip44 {
    //     pkt.extract(hdr.skip44);
    //     transition accept;
    // }

    // state skip48 {
    //     pkt.extract(hdr.skip48);
    //     transition accept;
    // }

    // state skip52 {
    //     pkt.extract(hdr.skip52);
    //     transition accept;
    // }

    // state skip56 {
    //     pkt.extract(hdr.skip56);
    //     transition accept;
    // }

    // state skip60 {
    //     pkt.extract(hdr.skip60);
    //     transition accept;
    // }

    // state skip64 {
    //     pkt.extract(hdr.skip64);
    //     transition accept;
    // }
}

#endif // UTIL_SKIP_PARSER_P4_GUARD
