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

extern void zero_init(const unsigned char nettype);

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
    const unsigned char rnd[32],
    unsigned char pkr[64]
);

extern char zero_pk2pkr_and_licr(
    const unsigned char pk[64],
    unsigned char pkr[64],
    unsigned char licr[ZERO_LIC_WIDTH]
);

extern char zero_check_licr(
    const unsigned char pkr[64],
    const unsigned char licr[ZERO_LIC_WIDTH]
);

extern char zero_ismy_pkr(
    const unsigned char pkr[64],
    const unsigned char tk[64],
    unsigned char r[32]
);

extern void zero_sign_pkr(
    const unsigned char h[32],
    const unsigned char seed[32],
    const unsigned char pkr[64],
    unsigned char s[64]
);

extern char zero_verify_pkr(
    const unsigned char h[32],
    const unsigned char s[64],
    const unsigned char pkr[64]
);


extern void zero_random32(unsigned char r[32]);

extern void zero_fee_str(char *p);

extern const char* zero_base58_enc(const unsigned char* p,int len);

extern char zero_base58_dec(const char* p,unsigned char* out,int len);


extern void zero_merkle_combine(
    const unsigned char d0[32],
    const unsigned char d1[32],
    unsigned char out[32]
);


extern void zero_out_commitment(
    const unsigned char tkn_currency[32],
    const unsigned char tkn_value[32],
    const unsigned char tkt_category[32],
    const unsigned char tkt_value[32],
    const unsigned char memo[ZERO_MEMO_WIDTH],
    const unsigned char pkr[64],
    const unsigned char ar[32],
    unsigned char cm[32]
);

extern void zero_root_commitment(
    unsigned long index,
    const unsigned char out_cm[32],
    unsigned char cm[32]
);


extern char zero_output(
    //---in---
    const unsigned char seed[32],
    const unsigned char tkn_currency[32],
    const unsigned char tkn_value[32],
    const unsigned char tkt_category[32],
    const unsigned char tkt_value[32],
    const unsigned char memo[64],
    const unsigned char pk[64],
    //---out---
    unsigned char asset_cm_ret[32],
    unsigned char ar_ret[32],
    unsigned char out_cm_ret[32],
    unsigned char einfo_ret[ZERO_INFO_WIDTH],
    unsigned char pkr[64],
    unsigned char proof[ZERO_PROOF_WIDTH]
);

extern void zero_enc_info(
    //---in---
    const unsigned char rsk[32],
    const unsigned char tkn_currency[32],
    const unsigned char tkn_value[32],
    const unsigned char tkt_category[32],
    const unsigned char tkt_value[32],
    const unsigned char ar[32],
    const unsigned char memo[64],
    //---out---
    unsigned char einfo_ret[ZERO_INFO_WIDTH],
    unsigned char asset_cm[32]
);

extern void zero_dec_einfo(
    //---in---
    const unsigned char rsk[32],
    const unsigned char einfo[ZERO_INFO_WIDTH],
    //---out---
    unsigned char tkn_currency_ret[32],
    unsigned char tkn_value_ret[32],
    unsigned char tkt_category_ret[32],
    unsigned char tkt_value_ret[32],
    unsigned char memo_ret[64],
    unsigned char asset_cm_ret[32]
);

extern void zero_til(
    const unsigned char tk[64],
    const unsigned char root_cm[32],
    unsigned char til[32]
);

extern char zero_input(
    //---in---
    const unsigned char seed[32],
    const unsigned char pkr[64],
    const unsigned char einfo[ZERO_INFO_WIDTH],
    unsigned long index,
    const unsigned char anchor[32],
    unsigned long position,
    const unsigned char path[ZERO_PATH_DEPTH*32],
    //---out---
    unsigned char ar_ret[32],
    unsigned char nil_ret[32],
    unsigned char til_ret[32],
    unsigned char proof_ret[ZERO_PROOF_WIDTH]
);

/*
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
*/

#ifdef __cplusplus
}
#endif

#endif //LIBZERO_ZERO_H
