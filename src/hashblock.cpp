#include "hashblock.h"

/* icochain: Combine stop 128-bits from each hash into a single hash */
inline uint256 CombineHashes(uint512 hash2, uint512 hash3)
{
    uint256 mask = uint256("0x8000000000000000000000000000000000000000000000000000000000000000");
    uint256 hash[2] = { hash2.trim256(), hash3.trim256() };

    /* Transpose first 128 bits of each hash into final */
    uint256 final = 0;
    for (unsigned int i = 0; i < 128; i++) {
        for (unsigned int j = 0; j < 2; j++) {
            final <<= 1;
            if ((hash[j] & mask) != 0)
                final |= 1;
        }
        mask >>= 1;
    }

    return final;
}

// icochain: 小企链自创算法，将两种SHA3并联使用
uint256 IHash(const char* pbegin, const char* pend)
{
    static unsigned char pblank[1];
    uint512 hashKeccak;
    sph_keccak512_context keccakCtx;
    sph_keccak512_init(&keccakCtx);
    sph_keccak512(&keccakCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    sph_keccak512_close(&keccakCtx, (void *)&hashKeccak);

    uint512 hashBlake;
    sph_blake512_context blakeCtx;
    sph_blake512_init(&blakeCtx);
    sph_blake512(&blakeCtx,(pbegin == pend ? pblank : (unsigned char*)&pbegin[0]),
                  (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&blakeCtx, (void *)&hashBlake);

    uint256 final = CombineHashes(hashKeccak, hashBlake);

    return final;
}
