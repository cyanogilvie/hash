/*
 * Areion ARM NEON Implementation
 *
 * Copyright (c) 2023 by Takanori Isobe, Ryoma Ito, Fukang Liu,
 * Kazuhiko Minematsu, Motoki Nakahashi, Kosei Sakamoto, Rentaro Shiba
 *
 * This work is based on the reference implementation from:
 * "Areion: Highly-Efficient Permutations and Its Applications (Extended Version)"
 * Published in: IACR Transactions on Cryptographic Hardware and Embedded Systems, 2023
 * DOI: 10.46586/tches.v2023.i2.115-154
 * Available at: https://eprint.iacr.org/2023/794
 *
 * Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0)
 * https://creativecommons.org/licenses/by/4.0/
 *
 * You are free to:
 * - Share — copy and redistribute the material in any medium or format
 * - Adapt — remix, transform, and build upon the material
 * for any purpose, even commercially.
 *
 * Under the following terms:
 * - Attribution — You must give appropriate credit, provide a link to the 
 *   license, and indicate if changes were made.
 */

#include <stdint.h>
#include <arm_neon.h>

/* Debug helper to print 128-bit values */
#if AREION_DEBUG
#include <stdio.h>
static void debug_print_uint8x16_t(const char* name, uint8x16_t val)
{
	uint8_t bytes[16];
	vst1q_u8(bytes, val);
	printf("%s: ", name);
	for (int i=0; i<16; i++)
		printf("%02x", bytes[i]);
	printf("\n");
}
#define DEBUG_PRINT_NEON(name, val) debug_print_uint8x16_t(name, val)
#else
#define DEBUG_PRINT_NEON(name, val)
#endif

/* Round Constants - X86 compatible ordering
 * X86 uses: RC0(i) = _mm_setr_epi32(RC[(i)*4+3], RC[(i)*4+2], RC[(i)*4+1], RC[(i)*4+0])
 * This means constants are loaded in reverse order within each round
 */
const uint32_t RC[15*4] = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
	0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
	0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
	0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
	0x801f2e28, 0x58efc166, 0x36920d87, 0x1574e690,
	0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
	0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
	0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0,
	0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
	0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27,
	0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
	0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6
};

/* Load round constants in X86-compatible order: RC[(i)*4+3], RC[(i)*4+2], RC[(i)*4+1], RC[(i)*4+0] */
static inline uint8x16_t RC0(int i)
{
    /* Create the same pattern as X86 _mm_setr_epi32(RC[(i)*4+3], RC[(i)*4+2], RC[(i)*4+1], RC[(i)*4+0]) */
    uint32_t temp[4] = { RC[(i)*4+3], RC[(i)*4+2], RC[(i)*4+1], RC[(i)*4+0] };
    return vreinterpretq_u8_u32(vld1q_u32(temp));
}
#define RC1(i) vmovq_n_u8(0)

/* Operations for the round function */
#define A1(X, K)	vaesmcq_u8((vaeseq_u8(X, K)))
#define A2(X, K)	vaeseq_u8(X, K)
#define A3(X)		vaesmcq_u8(X)
#define A4(X, K)	vaesdq_u8(X, K)
#define XOR(X, Y)	veorq_u8(X, Y)

/*
 * Corrected understanding of X86 AES-NI vs NEON instruction semantics:
 *
 * X86 AES-NI Operation Order: SubBytes → ShiftRows → MixColumns → AddRoundKey
 * NEON vaeseq: AddRoundKey → SubBytes → ShiftRows  
 * NEON vaesmcq: MixColumns
 *
 * To emulate X86 aesenc(input, key), we need:
 * 1. vaeseq_u8(input, zero) - does SubBytes, ShiftRows
 * 2. vaesmcq_u8(result) - does MixColumns
 * 3. veorq_u8(result, key) - does AddRoundKey last
 */

/* X86-compatible AES operations using NEON intrinsics */
#define NEON_AESENC(input, key) veorq_u8(vaesmcq_u8(vaeseq_u8(input, vmovq_n_u8(0))), key)

/* X86-compatible aesenclast (no MixColumns) */  
#define NEON_AESENCLAST(input, key) veorq_u8(vaeseq_u8(input, vmovq_n_u8(0)), key)

/* Round Function for the 256-bit permutation - Direct X86 emulation */
#define Round_Function_256(x0, x1, i) \
	do { \
		DEBUG_PRINT_NEON("NEON Round " #i " input x0", x0); \
		DEBUG_PRINT_NEON("NEON Round " #i " input x1", x1); \
		/* Direct X86 emulation: x1 = aesenc(aesenc(x0, RC0(i)), x1) */ \
		x1 = NEON_AESENC(NEON_AESENC(x0, RC0(i)), x1); \
		/* Direct X86 emulation: x0 = aesenclast(x0, RC1(i)) */ \
		x0 = NEON_AESENCLAST(x0, RC1(i)); \
		DEBUG_PRINT_NEON("NEON Round " #i " output x0", x0); \
		DEBUG_PRINT_NEON("NEON Round " #i " output x1", x1); \
	} while (0)

/* 256-bit permutation */
#define perm256(x0, x1) \
	do { \
		Round_Function_256(x0, x1, 0); \
		Round_Function_256(x1, x0, 1); \
		Round_Function_256(x0, x1, 2); \
		Round_Function_256(x1, x0, 3); \
		Round_Function_256(x0, x1, 4); \
		Round_Function_256(x1, x0, 5); \
		Round_Function_256(x0, x1, 6); \
		Round_Function_256(x1, x0, 7); \
		Round_Function_256(x0, x1, 8); \
		Round_Function_256(x1, x0, 9); \
	} while (0)

/* Inversed Round Function for the 256-bit permutation */
#define Inv_R_FIRST(x0, x1, i) \
	do { \
		x0 = A4(x0, RC1(i)); \
		x1 = A4(vaesmcq_u8(A2(vaesmcq_u8(A2(x0, RC0(i))), x1)), x1); \
	} while (0)

#define Inv_R_MIDDLE(x0, x1, i) \
	do { \
		x1 = A4(vaesmcq_u8(A2(vaesmcq_u8(A2(x0, RC0(i))), x1)), x1); \
	} while (0)
#define Inv_R_LAST(x0, x1, i) \
	do { \
		x1 = XOR(vaesmcq_u8(A2(vaesmcq_u8(A2(x0, RC0(i))), x1)), x1); \
	} while (0)

/* Inversed 256-bit permutation */
#define Inv_perm256(x0, x1) \
	do { \
		Inv_R_FIRST(x1, x0, 9); \
		Inv_R_MIDDLE(x0, x1, 8); \
		Inv_R_MIDDLE(x1, x0, 7); \
		Inv_R_MIDDLE(x0, x1, 6); \
		Inv_R_MIDDLE(x1, x0, 5); \
		Inv_R_MIDDLE(x0, x1, 4); \
		Inv_R_MIDDLE(x1, x0, 3); \
		Inv_R_MIDDLE(x0, x1, 2); \
		Inv_R_MIDDLE(x1, x0, 1); \
		Inv_R_LAST(x0, x1, 0); \
	} while (0)

/* Round Function for the 512-bit permutation - Direct X86 emulation */
#define Round_Function_512(x0, x1, x2, x3, i) \
	do { \
		x1 = NEON_AESENC(x0, x1); \
		x3 = NEON_AESENC(x2, x3); \
		x0 = NEON_AESENCLAST(x0, RC1(i)); \
		x2 = NEON_AESENC(NEON_AESENCLAST(x2, RC0(i)), RC1(i)); \
	} while (0)

/* 512-bit permutation */
#define perm512(x0, x1, x2, x3) \
	do { \
		Round_Function_512(x0, x1, x2, x3, 0); \
		Round_Function_512(x1, x2, x3, x0, 1); \
		Round_Function_512(x2, x3, x0, x1, 2); \
		Round_Function_512(x3, x0, x1, x2, 3); \
		Round_Function_512(x0, x1, x2, x3, 4); \
		Round_Function_512(x1, x2, x3, x0, 5); \
		Round_Function_512(x2, x3, x0, x1, 6); \
		Round_Function_512(x3, x0, x1, x2, 7); \
		Round_Function_512(x0, x1, x2, x3, 8); \
		Round_Function_512(x1, x2, x3, x0, 9); \
		Round_Function_512(x2, x3, x0, x1, 10); \
		Round_Function_512(x3, x0, x1, x2, 11); \
		Round_Function_512(x0, x1, x2, x3, 12); \
		Round_Function_512(x1, x2, x3, x0, 13); \
		Round_Function_512(x2, x3, x0, x1, 14); \
	} while (0)

