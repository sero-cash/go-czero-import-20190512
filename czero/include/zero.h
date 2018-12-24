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

extern void zero_init(const char* account_dir,const unsigned char nettype);

extern void zero_log_bytes(const unsigned char* bytes,int len);

extern void zero_seed2tk(
    const unsigned char seed[32],
    unsigned char tk[ZERO_TK_WIDTH]
);

extern void zero_seed2pk(
    const unsigned char seed[32],
    unsigned char pk[ZERO_PK_WIDTH]
);

extern void zero_pk2pkr(
    const unsigned char pk[ZERO_PK_WIDTH],
    const unsigned char rnd[32],
    unsigned char pkr[ZERO_PKr_WIDTH]
);

extern char zero_pk2pkr_and_licr(
    const unsigned char pk[ZERO_PK_WIDTH],
    unsigned char pkr[ZERO_PKr_WIDTH],
    unsigned char licr[ZERO_LIC_WIDTH]
);

extern void zero_hpkr(
    const unsigned char pkr[ZERO_PKr_WIDTH],
    unsigned char hpkr[ZERO_HPKr_WIDTH]
);

extern char zero_check_licr(
    const unsigned char pkr[ZERO_PKr_WIDTH],
    const unsigned char licr[ZERO_LIC_WIDTH]
);

extern char zero_ismy_pkr(
    const unsigned char pkr[ZERO_PKr_WIDTH],
    const unsigned char tk[ZERO_TK_WIDTH]
);

extern void zero_sign_pkr(
    const unsigned char h[32],
    const unsigned char seed[32],
    const unsigned char pkr[ZERO_PKr_WIDTH],
    unsigned char s[64]
);

extern char zero_verify_pkr(
    const unsigned char h[32],
    const unsigned char s[64],
    const unsigned char pkr[ZERO_PKr_WIDTH]
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
    const unsigned char pkr[ZERO_PKr_WIDTH],
    const unsigned char rsk[32],
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
    const unsigned char pkr[ZERO_PKr_WIDTH],
    //---out---
    unsigned char asset_cm_ret[32],
    unsigned char ar_ret[32],
    unsigned char out_cm_ret[32],
    unsigned char einfo_ret[ZERO_INFO_WIDTH],
    unsigned char sbase_ret[32],
    unsigned char proof_ret[ZERO_PROOF_WIDTH]
);

extern void zero_gen_asset_cc(
    //---in---
    const unsigned char tkn_currency[32],
    const unsigned char tkn_value[32],
    const unsigned char tkt_category[32],
    const unsigned char tkt_value[32],
    unsigned char asset_cc_ret[32]
);

extern void zero_enc_info(
    //---in---
    const unsigned char key[32],
    const unsigned char tkn_currency[32],
    const unsigned char tkn_value[32],
    const unsigned char tkt_category[32],
    const unsigned char tkt_value[32],
    const unsigned char rsk[32],
    const unsigned char memo[64],
    //---out---
    unsigned char einfo_ret[ZERO_INFO_WIDTH]
);


extern void zero_fetch_key(
    const unsigned char tk[ZERO_TK_WIDTH],
    const unsigned char rpk[32],
    const unsigned char key[32]
);

extern void zero_dec_einfo(
    //---in---
    const unsigned char key[32],
    const unsigned char einfo[ZERO_INFO_WIDTH],
    //---out---
    unsigned char tkn_currency_ret[32],
    unsigned char tkn_value_ret[32],
    unsigned char tkt_category_ret[32],
    unsigned char tkt_value_ret[32],
    unsigned char rsk_ret[32],
    unsigned char memo_ret[64]
);

extern void zero_til(
    const unsigned char tk[ZERO_TK_WIDTH],
    const unsigned char root_cm[32],
    unsigned char til[32]
);

extern char zero_input(
    //---in---
    const unsigned char seed[32],
    const unsigned char pkr[ZERO_PKr_WIDTH],
    const unsigned char sbase[32],
    const unsigned char einfo[ZERO_INFO_WIDTH],
    unsigned long index,
    const unsigned char anchor[32],
    unsigned long position,
    const unsigned char path[ZERO_PATH_DEPTH*32],
    //---out---
    unsigned char asset_cm_ret[32],
    unsigned char ar_ret[32],
    unsigned char nil_ret[32],
    unsigned char til_ret[32],
    unsigned char proof_ret[ZERO_PROOF_WIDTH]
);

extern void zero_sign_balance(
    //---in---
    int zin_size,
    const unsigned char* zin_acms,
    const unsigned char* zin_ars,
    int zout_size,
    const unsigned char* zout_acms,
    const unsigned char* zout_ars,
    int oin_size,
    const unsigned char* oin_accs,
    int oout_size,
    const unsigned char* oout_accs,
    const unsigned char hash[32],
    //---out---
    unsigned char bsign[64],
    unsigned char bcr[32]
);

extern char zero_verify_balance(
    int zin_size,
    const unsigned char* zin_acms,
    int zout_size,
    const unsigned char* zout_acms,
    int oin_size,
    const unsigned char* oin_accs,
    int oout_size,
    const unsigned char* oout_accs,
    const unsigned char hash[32],
    const unsigned char bcr[32],
    const unsigned char bsign[64]
);

extern char zero_output_verify(
    const unsigned char asset_cm[32],
    const unsigned char out_cm[32],
    const unsigned char rpk[32],
    const unsigned char proof[ZERO_PROOF_WIDTH]
);

extern char zero_input_verify(
    const unsigned char asset_cm[32],
    const unsigned char anchor[32],
    const unsigned char nil[32],
    const unsigned char proof[ZERO_PROOF_WIDTH]
);


#ifdef __cplusplus
}
#endif

#endif //LIBZERO_ZERO_H
