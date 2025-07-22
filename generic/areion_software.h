/*
* Software-only Areion Implementation
*
* Pure C implementation using lookup tables and bit operations.
* This serves as:
* 1. A reference implementation for debugging platform-specific issues
* 2. A fallback for platforms without AES-NI or NEON support (RISC-V, etc.)
* 3. A way to exactly match X86 AES instruction behavior
*/

#include <stdint.h>
#include <string.h>
#if AREION_DEBUG
#	include <stdio.h>
#endif

// Debug helper to print 128-bit values
#if AREION_DEBUG
static void debug_print_sw_state(const char* name, const uint8_t state[16]) //<<<
{
	printf("%s: ", name);
	for (int i=0; i<16; i++)
		printf("%02x", state[i]);
	printf("\n");
}
//>>>
#define DEBUG_PRINT_SW(name, state) debug_print_sw_state(name, state)
#else
#define DEBUG_PRINT_SW(name, state)
#endif


// AES S-box lookup table
static const uint8_t sw_sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* X86-specific round constants - exact translation of X86 _mm_setr_epi32 pattern
 * X86 code: RC0(i) = _mm_setr_epi32(RC[(i)*4+3], RC[(i)*4+2], RC[(i)*4+1], RC[(i)*4+0])
 * This means for round 0: RC[3], RC[2], RC[1], RC[0] stored in little-endian order
 */
static const uint8_t x86_round_constants[15][16] = {
	// Round 0: RC[3], RC[2], RC[1], RC[0] in LE bytes
	// RC[3]=0x03707344, RC[2]=0x13198a2e, RC[1]=0x85a308d3, RC[0]=0x243f6a88
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	// Round 1: RC[7], RC[6], RC[5], RC[4]
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	// Round 2: RC[11], RC[10], RC[9], RC[8]
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	// Continue pattern for all 15 rounds...
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
	{0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
	{0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
	{0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
	{0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
	{0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57}
};


/* Software implementation of AES operations */
static inline void sw_subbytes(uint8_t state[16]) //<<<
{
	for (int i=0; i<16; i++)
		state[i] = sw_sbox[state[i]];
}

//>>>
static inline void sw_shiftrows(uint8_t state[16]) //<<<
{
	uint8_t temp[16];
	// Row 0: no shift
	temp[0] = state[0];  temp[4] = state[4];  temp[8] = state[8];  temp[12] = state[12];
	// Row 1: left shift by 1
	temp[1] = state[5];  temp[5] = state[9];  temp[9] = state[13]; temp[13] = state[1];
	// Row 2: left shift by 2  
	temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
	// Row 3: left shift by 3
	temp[3] = state[15]; temp[7] = state[3];  temp[11] = state[7]; temp[15] = state[11];
	memcpy(state, temp, 16);
}

//>>>
static inline uint8_t gf_mult(uint8_t a, uint8_t b) // Galois Field multiplication for MixColumns <<<
{
	uint8_t	result = 0;
	for (int i=0; i<8; i++) {
		if (b & 1) result ^= a;
		uint8_t hi_bit = a & 0x80;
		a <<= 1;
		if (hi_bit) a ^= 0x1b; // AES irreducible polynomial
		b >>= 1;
	}
	return result;
}

//>>>
static inline void sw_mixcolumns(uint8_t state[16]) //<<<
{
	uint8_t temp[16];

	for (int col = 0; col < 4; col++) {
		uint8_t s0 = state[col*4 + 0];
		uint8_t s1 = state[col*4 + 1]; 
		uint8_t s2 = state[col*4 + 2];
		uint8_t s3 = state[col*4 + 3];

		temp[col*4 + 0] = gf_mult(0x02, s0) ^ gf_mult(0x03, s1) ^ s2 ^ s3;
		temp[col*4 + 1] = s0 ^ gf_mult(0x02, s1) ^ gf_mult(0x03, s2) ^ s3;
		temp[col*4 + 2] = s0 ^ s1 ^ gf_mult(0x02, s2) ^ gf_mult(0x03, s3);
		temp[col*4 + 3] = gf_mult(0x03, s0) ^ s1 ^ s2 ^ gf_mult(0x02, s3);
	}
	memcpy(state, temp, 16);
}

//>>>

/* X86 AES-NI compatible operations */
static inline void x86_aesenc(uint8_t state[16], const uint8_t key[16]) //<<<
{
	// X86 AES-NI order: SubBytes → ShiftRows → MixColumns → AddRoundKey  
	sw_subbytes(state);
	sw_shiftrows(state);
	sw_mixcolumns(state);
	for (int i=0; i<16; i++)
		state[i] ^= key[i];
}

//>>>
static inline void x86_aesenclast(uint8_t state[16], const uint8_t key[16]) //<<<
{
	// X86 AES-NI order: SubBytes → ShiftRows → AddRoundKey (no MixColumns)
	sw_subbytes(state);
	sw_shiftrows(state);
	for (int i=0; i<16; i++)
		state[i] ^= key[i];
}

//>>>

/* X86-compatible round function for software implementation */
static inline void sw_x86_round_function_256(uint8_t x0[16], uint8_t x1[16], int round) //<<<
{
	uint8_t		temp_x0[16], temp_x1[16];

	// Make copies for the computation
	memcpy(temp_x0, x0, 16);
	memcpy(temp_x1, x1, 16);

	// F2: x1 = aesenc(aesenc(x0, RC0(round)), x1)
	// Step 1: temp_x0 = aesenc(x0, RC0(round))
	x86_aesenc(temp_x0, x86_round_constants[round]);

	// Step 2: x1 = aesenc(temp_x0, x1)
	x86_aesenc(temp_x0, temp_x1);
	memcpy(x1, temp_x0, 16);

	// F1: x0 = aesenclast(x0, RC1(round)) [RC1 is always zero]
	static const uint8_t zero_key[16] = {0};
	x86_aesenclast(x0, zero_key);
}

//>>>
static inline void sw_perm256_x86_compatible(uint8_t x0[16], uint8_t x1[16]) //<<<
{
	sw_x86_round_function_256(x0, x1, 0);
	sw_x86_round_function_256(x1, x0, 1);
	sw_x86_round_function_256(x0, x1, 2);
	sw_x86_round_function_256(x1, x0, 3);
	sw_x86_round_function_256(x0, x1, 4);
	sw_x86_round_function_256(x1, x0, 5);
	sw_x86_round_function_256(x0, x1, 6);
	sw_x86_round_function_256(x1, x0, 7);
	sw_x86_round_function_256(x0, x1, 8);
	sw_x86_round_function_256(x1, x0, 9);
}

//>>>

/* X86-compatible round function for 512-bit permutation */
static inline void sw_x86_round_function_512(uint8_t x0[16], uint8_t x1[16], uint8_t x2[16], uint8_t x3[16], int round) //<<<
{
	uint8_t temp_x0[16], temp_x2[16], temp_x2_after_aesenclast[16];
	static const uint8_t zero_key[16] = {0};

	// Make copies for computation
	memcpy(temp_x0, x0, 16);
	memcpy(temp_x2, x2, 16);

	// First operation: x1 = aesenc(x0, x1)
	x86_aesenc(temp_x0, x1);
	memcpy(x1, temp_x0, 16);

	// Second operation: x3 = aesenc(x2, x3)  
	x86_aesenc(temp_x2, x3);
	memcpy(x3, temp_x2, 16);

	// Third operation: x0 = aesenclast(x0, RC1(round)) [RC1 is always zero]
	x86_aesenclast(x0, zero_key);

	// Fourth operation: x2 = aesenc(aesenclast(x2, RC0(round)), RC1(round))
	// Step 1: temp_x2_after_aesenclast = aesenclast(x2, RC0(round))
	memcpy(temp_x2_after_aesenclast, x2, 16);
	x86_aesenclast(temp_x2_after_aesenclast, x86_round_constants[round]);
	// Step 2: x2 = aesenc(temp_x2_after_aesenclast, RC1(round)) [RC1 is zero]
	x86_aesenc(temp_x2_after_aesenclast, zero_key);
	memcpy(x2, temp_x2_after_aesenclast, 16);
}

//>>>
static inline void sw_perm512_x86_compatible(uint8_t x0[16], uint8_t x1[16], uint8_t x2[16], uint8_t x3[16]) //<<<
{
	// Exact pattern from X86 perm512 macro
	sw_x86_round_function_512(x0, x1, x2, x3, 0);
	sw_x86_round_function_512(x1, x2, x3, x0, 1);
	sw_x86_round_function_512(x2, x3, x0, x1, 2);
	sw_x86_round_function_512(x3, x0, x1, x2, 3);
	sw_x86_round_function_512(x0, x1, x2, x3, 4);
	sw_x86_round_function_512(x1, x2, x3, x0, 5);
	sw_x86_round_function_512(x2, x3, x0, x1, 6);
	sw_x86_round_function_512(x3, x0, x1, x2, 7);
	sw_x86_round_function_512(x0, x1, x2, x3, 8);
	sw_x86_round_function_512(x1, x2, x3, x0, 9);
	sw_x86_round_function_512(x2, x3, x0, x1, 10);
	sw_x86_round_function_512(x3, x0, x1, x2, 11);
	sw_x86_round_function_512(x0, x1, x2, x3, 12);
	sw_x86_round_function_512(x1, x2, x3, x0, 13);
	sw_x86_round_function_512(x2, x3, x0, x1, 14);
}

//>>>

/* Software equivalent of permute_areion_512 - includes reordering */
static inline void sw_permute_areion_512_x86_compatible(uint8_t dst[64], const uint8_t src[64]) //<<<
{
	uint8_t x0[16], x1[16], x2[16], x3[16];

	// Load input
	memcpy(x0, src,      16);
	memcpy(x1, src + 16, 16);
	memcpy(x2, src + 32, 16);
	memcpy(x3, src + 48, 16);

	// Apply permutation
	sw_perm512_x86_compatible(x0, x1, x2, x3);

	// Store with X86 reordering: dst = {x3, x0, x1, x2}
	memcpy(dst,      x3, 16);  // dst[0] = x3
	memcpy(dst + 16, x0, 16);  // dst[1] = x0
	memcpy(dst + 32, x1, 16);  // dst[2] = x1
	memcpy(dst + 48, x2, 16);  // dst[3] = x2
}

//>>>

/* X86-compatible macro definitions for software fallback */
#define perm256(x0, x1) sw_perm256_x86_compatible(x0, x1)
#define perm512(x0, x1, x2, x3) sw_perm512_x86_compatible(x0, x1, x2, x3)
#define permute_areion_512(dst, src) sw_permute_areion_512_x86_compatible((uint8_t*)(dst), (const uint8_t*)(src))

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4 noexpandtab
