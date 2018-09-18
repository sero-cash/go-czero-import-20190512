/** @file
 *****************************************************************************
 * @author     This file is part of czero, developed by sero.cash
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/


#ifndef LIBZERO_ZERO_H
#define LIBZERO_ZERO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "constant.h"

extern void zero_init();

extern void zero_log_bytes(const unsigned char* bytes,int len);

extern void zero_seed2tk(
    const unsigned char seed[32],
    unsigned char tk[64]
);

extern void zero_seed2pk(
    const unsigned char seed[32],
    unsigned char pk[64]
);

extern void zero_pk2pkr(
    const unsigned char pk[64],
    const unsigned char r[32],
    unsigned char pkr[64]
);

extern void zero_random32(unsigned char r[32]);

extern void zero_fee_str(char *p);

extern const char* zero_base58_enc(const unsigned char* p,int len);

extern char zero_base58_dec(const char* p,unsigned char* out,int len);

extern void zero_sha256_one(const unsigned char* d,unsigned char* out);

extern void zero_sha256_two(const unsigned char* d0,const unsigned char* d1,unsigned char* out);

extern void zero_gen_commitment(
    const unsigned char currency[32],
    const unsigned char pkr[64],
    const unsigned char value[32],
    const unsigned char text[64],
    unsigned char commitment[32]
);

extern char zero_gen_desc_z(
    const unsigned char seed[32],
    const unsigned char hash_o[32],
    const unsigned char currency[32],
    const unsigned char c0[32],
    const unsigned char c1[32],
    //----pre---
    unsigned int pre_i,
    const unsigned char pre_r[32],
    const unsigned char pre_zi_0[32],
    const unsigned char pre_zi_1[32],
    //----extra---
    const unsigned char extra_o_0[32],
    const unsigned char extra_o_1[32],
    unsigned int extra_i,
    const unsigned char extra_zo_0[32],
    const unsigned char extra_zo_1[32],
    const unsigned char extra_r[32],
    unsigned char extra_s1_ret[32],
    //----out----
    const unsigned char out_addr[64],
    const unsigned char out_value[32],
    const unsigned char out_info[ZERO_MEMO_WIDTH],
    unsigned char out_einfo_ret[ZERO_EINFO_WIDTH],
    unsigned char out_commitment_ret[32],
    //----in----
    const unsigned char in_einfo[ZERO_EINFO_WIDTH],
    const unsigned char in_commitment[32],
    const unsigned char in_path[ZERO_PATH_DEPTH*32],
    unsigned int in_index,
    const unsigned char in_s1[32],
    const unsigned char in_anchor[32],
    unsigned char in_nil_ret[32],
    unsigned char in_trace_ret[32],
    //-----------
    unsigned char proof[ZERO_PROOF_WIDTH]
);


extern char zero_ismy_pkr(
    const unsigned char pkr[64],
    const unsigned char tk[64]
);

extern char zero_en_einfo(
    const unsigned char pkr[64],
    const unsigned char tk[64],
    const unsigned char currency[32],
    const unsigned char text[64],
    const unsigned char v[32],
    unsigned char einfo[64*2],
    unsigned char r[32],
    unsigned char commitment[32],
    unsigned char trace[32]
);

extern char zero_de_einfo(
    const unsigned char vsk[32],
    const unsigned char zpk[32],
    const unsigned char einfo[ZERO_EINFO_WIDTH],
    const unsigned char s1[32],
    const unsigned char commitment[32],
    unsigned char currency[32],
    unsigned char text[64],
    unsigned char r[32],
    unsigned char v[32],
    unsigned char trace[32]
);

extern char zero_verify_desc_z(
    const unsigned char hash_o[32],
    //----pre----
    unsigned int pre_i,
    const unsigned char pre_s1[32],
    //----extra----
    const unsigned char extra_o_0[32],
    const unsigned char extra_o_1[32],
    unsigned int extra_i,
    const unsigned char extra_s1[32],
    //----out----
    const unsigned char out_commitment[32],
    //----in----
    const unsigned char in_anchor[32],
    const unsigned char in_nil[32],
    //----------
    const unsigned char proof[ZERO_PROOF_WIDTH]
);

#ifdef __cplusplus
}
#endif

#endif //LIBZERO_ZERO_H
