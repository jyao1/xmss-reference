#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

/* These are merely internal identifiers for the supported hash functions. */
#define XMSS_SHA2 0
#define XMSS_SHAKE128 1
#define XMSS_SHAKE256 2

/* This is a result of the OID definitions in the draft; needed for parsing. */
#define XMSS_OID_LEN 4

#define XMSS_PARAM_MAX_n                64
#define XMSS_PARAM_MAX_padding_len      64
#define XMSS_PARAM_MAX_wots_w           256
#define XMSS_PARAM_MAX_wots_log_w       8
#define XMSS_PARAM_MAX_wots_len1        256
#define XMSS_PARAM_MAX_wots_len2        5
#define XMSS_PARAM_MAX_wots_len         (XMSS_PARAM_MAX_wots_len1 + XMSS_PARAM_MAX_wots_len2)
#define XMSS_PARAM_MAX_wots_sig_bytes   (XMSS_PARAM_MAX_wots_len * XMSS_PARAM_MAX_n)
#define XMSS_PARAM_MAX_full_height      60
#define XMSS_PARAM_MAX_tree_height      60
#define XMSS_PARAM_MAX_d                12
#define XMSS_PARAM_MAX_index_bytes      8
#define XMSS_PARAM_MAX_sig_bytes        (XMSS_PARAM_MAX_index_bytes + XMSS_PARAM_MAX_n + XMSS_PARAM_MAX_d * XMSS_PARAM_MAX_wots_sig_bytes + XMSS_PARAM_MAX_full_height * XMSS_PARAM_MAX_n)
#define XMSS_PARAM_MAX_pk_bytes         (2 * XMSS_PARAM_MAX_n)
#define XMSS_PARAM_MAX_sk_bytes         (XMSS_PARAM_MAX_index_bytes + 4 * XMSS_PARAM_MAX_n \
                                        + (2 * XMSS_PARAM_MAX_d - 1) * ( \
                                          (XMSS_PARAM_MAX_tree_height + 1) * XMSS_PARAM_MAX_n \
                                           + 4 \
                                           + XMSS_PARAM_MAX_tree_height + 1 \
                                           + XMSS_PARAM_MAX_tree_height * XMSS_PARAM_MAX_n \
                                           + (XMSS_PARAM_MAX_tree_height >> 1) * XMSS_PARAM_MAX_n \
                                           + (XMSS_PARAM_MAX_tree_height - XMSS_PARAM_MAX_bds_k) * (7 + XMSS_PARAM_MAX_n) \
                                           + ((1 << XMSS_PARAM_MAX_bds_k) - XMSS_PARAM_MAX_bds_k - 1) * XMSS_PARAM_MAX_n \
                                           + 4 \
                                          ) \
                                        + (XMSS_PARAM_MAX_d - 1) * XMSS_PARAM_MAX_wots_sig_bytes)
#define XMSS_PARAM_MAX_bds_k            0

/* This structure will be populated when calling xmss[mt]_parse_oid. */
typedef struct {
    unsigned int func;
    unsigned int n;              // = 32, 64
    unsigned int padding_len;    // = 4, 32, 64
    unsigned int wots_w;         // = 4, 16, 256
    unsigned int wots_log_w;     // = 2, 4, 8
    unsigned int wots_len1;      // = 8 * n / wots_log_w = 32, 64, 128, 256
    unsigned int wots_len2;      // = 5, 3, 2
    unsigned int wots_len;       // = wots_len1 + wots_len2 = 261
    unsigned int wots_sig_bytes; // = wots_len * n = 261 * 64;
    unsigned int full_height;    // = 10, 16, 20, 40, 60
    unsigned int tree_height;    // = full_height / d = [1, 60]
    unsigned int d;              // = 1, 2, 4, 8, 3, 6, 12, 
    unsigned int index_bytes;    // = 4 or (full_height + 7) / 8 = [2, 3, 4, 5, 8]
    unsigned int sig_bytes;      // = index_bytes + n + d * wots_sig_bytes + full_height * n
    unsigned int pk_bytes;       // = 2 * n = 64, 128
    unsigned long long sk_bytes; // = index_bytes + 4 * n
                                 //     + (2 * d - 1) * (
                                 //       (tree_height + 1) * n
                                 //        + 4
                                 //        + tree_height + 1
                                 //        + tree_height * n
                                 //        + (tree_height >> 1) * n
                                 //        + (tree_height - bds_k) * (7 + n)
                                 //        + ((1 << bds_k) - bds_k - 1) * n
                                 //        + 4
                                 //       )
                                 //     + (d - 1) * wots_sig_bytes;
    unsigned int bds_k;          // = 0
} xmss_params;

/**
 * Accepts strings such as "XMSS-SHA2_10_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmss_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts takes strings such as "XMSSMT-SHA2_20/2_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmssmt_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmss_parse_oid(xmss_params *params, const uint32_t oid);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmssmt_parse_oid(xmss_params *params, const uint32_t oid);


/* Given a params struct where the following properties have been initialized;
    - full_height; the height of the complete (hyper)tree
    - n; the number of bytes of hash function output
    - d; the number of layers (d > 1 implies XMSSMT)
    - func; one of {XMSS_SHA2, XMSS_SHAKE128, XMSS_SHAKE256}
    - wots_w; the Winternitz parameter
    - optionally, bds_k; the BDS traversal trade-off parameter,
    this function initializes the remainder of the params structure. */
int xmss_xmssmt_initialize_params(xmss_params *params);

#endif
