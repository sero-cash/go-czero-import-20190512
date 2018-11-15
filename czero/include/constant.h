/** @file
 *****************************************************************************
 * @author     This file is part of czero, developed by sero.cash
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LIBZERO_CONSTANT_H
#define LIBZERO_CONSTANT_H

enum {
    ZERO_PATH_DEPTH=18,
    ZERO_PROOF_WIDTH=131,
    ZERO_MEMO_WIDTH=64,
    ZERO_EINFO_WIDTH=32*5,
    ZERO_INFO_WIDTH=
            32+ //currency
            32+ //value
            32+ //category
            32+ //value
            32+ //ar
            64, //memo
    ZERO_LIC_WIDTH=ZERO_PROOF_WIDTH,
};

#endif //LIBZERO_CONSTANT_H
