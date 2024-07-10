#ifndef INTERNAL_HEADERS_P4_GUARD
#define INTERNAL_HEADERS_P4_GUARD

////////////////////////////
// Internal Bridge Header //
///////////////////////////

enum bit<4> header_type_t {
    BRIDGE = 1,
    EG_MIRROR = 2
}

typedef bit<4> header_info_t;

#define INTERNAL_HDR_FIELDS \
    header_type_t int_hdr_type; \
    header_info_t int_hdr_info

header int_header_h {
    INTERNAL_HDR_FIELDS;
}

//////////////////
// Mirror Types //
//////////////////

#define EGR_PORT_MIRROR 1

#endif // INTERNAL_HEADERS_P4_GUARD
