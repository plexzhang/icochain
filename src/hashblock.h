// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_HASHBLOCK_H
#define BITCOIN_HASHBLOCK_H

#include "uint256.h"
#include "sph_keccak.h"
#include "sph_blake.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>
#include "bignum.h"

#include <stdio.h>

class CBlock;
typedef struct
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;

} block_header;

// icochain: 小企链自创算法，将两种SHA3并联使用
uint256 IHash(const char* pbegin, const char* pend);

#endif
