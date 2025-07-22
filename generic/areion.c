#include "hashInt.h"
#include "areion.h"

static inline void aerion_trunc(const uint64_t input[8], uint64_t output[4]) //<<<
{
	output[0] = input[1];
	output[1] = input[3];
	output[2] = input[4];
	output[3] = input[6];
}

//>>>

// VIL construction (Merkle-Damgård) <<<
static inline void vil_init(vil_context*restrict ctx) //<<<
{
	*ctx = (vil_context){
		.state = {
			0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
			0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
		}
	};
}

//>>>
static inline void vil_compress(vil_context*restrict ctx, const uint8_t block[32]) //<<<
{
	uint8_t	tmp[64];

#if HAVE_AES_NI
	__m128i x[4] = {
		_mm_loadu_si128((__m128i*)(block)),
		_mm_loadu_si128((__m128i*)(block + 16)),
		_mm_loadu_si128((__m128i*)(ctx->state)),
		_mm_loadu_si128((__m128i*)(ctx->state + 16))
	};
	__m128i orig_x0 = x[0];
	__m128i orig_x1 = x[1];
	__m128i orig_x2 = x[2];
	__m128i orig_x3 = x[3];

	__m128i	out[4];
	permute_areion_512(out, x);
	x[0] = _mm_xor_si128(out[0], orig_x0);
	x[1] = _mm_xor_si128(out[1], orig_x1);
	x[2] = _mm_xor_si128(out[2], orig_x2);
	x[3] = _mm_xor_si128(out[3], orig_x3);

	_mm_storeu_si128((__m128i*) tmp,       x[0]);
	_mm_storeu_si128((__m128i*)(tmp + 16), x[1]);
	_mm_storeu_si128((__m128i*)(tmp + 32), x[2]);
	_mm_storeu_si128((__m128i*)(tmp + 48), x[3]);
#elif HAVE_AES_NEON
	uint8x16_t x0 = vld1q_u8(block);
	uint8x16_t x1 = vld1q_u8(block + 16);
	uint8x16_t x2 = vld1q_u8(ctx->state);
	uint8x16_t x3 = vld1q_u8(ctx->state + 16);
	uint8x16_t orig_x0 = x0;
	uint8x16_t orig_x1 = x1;
	uint8x16_t orig_x2 = x2;
	uint8x16_t orig_x3 = x3;

	perm512(x0, x1, x2, x3);

	// Match X86 exactly: permute_areion_512 reorders to {x3, x0, x1, x2} then XORs with original
	uint8x16_t perm_x0 = x0, perm_x1 = x1, perm_x2 = x2, perm_x3 = x3;
	x0 = veorq_u8(perm_x3, orig_x0);  // out[0] = x3_permuted XOR orig_x0
	x1 = veorq_u8(perm_x0, orig_x1);  // out[1] = x0_permuted XOR orig_x1
	x2 = veorq_u8(perm_x1, orig_x2);  // out[2] = x1_permuted XOR orig_x2
	x3 = veorq_u8(perm_x2, orig_x3);  // out[3] = x2_permuted XOR orig_x3

	vst1q_u8(tmp,      x0);
	vst1q_u8(tmp + 16, x1);
	vst1q_u8(tmp + 32, x2);
	vst1q_u8(tmp + 48, x3);
#else
	// Software fallback implementation
	uint8_t x0[16], x1[16], x2[16], x3[16];
	uint8_t orig_x0[16], orig_x1[16], orig_x2[16], orig_x3[16];
	
	memcpy(x0, block,      16);
	memcpy(x1, block + 16, 16);
	memcpy(x2, ctx->state,      16);
	memcpy(x3, ctx->state + 16, 16);
	memcpy(orig_x0, x0, 16);
	memcpy(orig_x1, x1, 16);
	memcpy(orig_x2, x2, 16);
	memcpy(orig_x3, x3, 16);
	
	perm512(x0, x1, x2, x3);
	// Match X86 exactly: permute_areion_512 reorders to {x3, x0, x1, x2} then XORs with original
	uint8_t perm_x0[16], perm_x1[16], perm_x2[16], perm_x3[16];
	memcpy(perm_x0, x0, 16);
	memcpy(perm_x1, x1, 16);
	memcpy(perm_x2, x2, 16);
	memcpy(perm_x3, x3, 16);
	
	for (int i=0; i<16; i++) {
		x0[i] = perm_x3[i] ^ orig_x0[i];  // out[0] = x3_permuted XOR orig_x0
		x1[i] = perm_x0[i] ^ orig_x1[i];  // out[1] = x0_permuted XOR orig_x1  
		x2[i] = perm_x1[i] ^ orig_x2[i];  // out[2] = x1_permuted XOR orig_x2
		x3[i] = perm_x2[i] ^ orig_x3[i];  // out[3] = x2_permuted XOR orig_x3
	}
	
	memcpy(tmp,      x0, 16);
	memcpy(tmp + 16, x1, 16);
	memcpy(tmp + 32, x2, 16);
	memcpy(tmp + 48, x3, 16);
#endif

	aerion_trunc((const uint64_t*)tmp, (uint64_t*)ctx->state);
}

//>>>
static inline void vil_update(vil_context*restrict ctx, const uint8_t*restrict data, uint64_t len) //<<<
{
	ctx->total_len += len;

	if (ctx->buffer_len + len < 32) {
		memcpy(ctx->buffer + ctx->buffer_len, data, len);
		ctx->buffer_len += len;
		return;
	}

	if (ctx->buffer_len > 0) {
		const uint32_t	needed = 32 - ctx->buffer_len;
		memcpy(ctx->buffer + ctx->buffer_len, data, needed);
		vil_compress(ctx, ctx->buffer);
		data += needed;
		len  -= needed;
		ctx->buffer_len = 0;
	}

	while (len >= 32) {
		vil_compress(ctx, data);
		data += 32;
		len  -= 32;
	}

	if (len > 0) {
		memcpy(ctx->buffer, data, len);
		ctx->buffer_len = len;
	}
}

//>>>
static inline void vil_final(vil_context*restrict ctx, uint8_t output[32]) //<<<
{
	uint8_t		final_block[32];
	uint32_t	pad_len;

	if (ctx->buffer_len < 24) {
		pad_len = 24 - ctx->buffer_len;
		memcpy(final_block, ctx->buffer, ctx->buffer_len);
		memset(final_block + ctx->buffer_len, 0, pad_len);
		final_block[ctx->buffer_len] = 0x80;
	} else {
		pad_len = 32 - ctx->buffer_len;
		memcpy(final_block, ctx->buffer, ctx->buffer_len);
		memset(final_block + ctx->buffer_len, 0, pad_len);
		final_block[ctx->buffer_len] = 0x80;
		vil_compress(ctx, final_block);
		memset(final_block, 0, 24);
	}

	const uint64_t	bit_len = ctx->total_len * 8;
	final_block[24] = (bit_len >> 56) & 0xFF;
	final_block[25] = (bit_len >> 48) & 0xFF;
	final_block[26] = (bit_len >> 40) & 0xFF;
	final_block[27] = (bit_len >> 32) & 0xFF;
	final_block[28] = (bit_len >> 24) & 0xFF;
	final_block[29] = (bit_len >> 16) & 0xFF;
	final_block[30] = (bit_len >>  8) & 0xFF;
	final_block[31] =  bit_len        & 0xFF;

	vil_compress(ctx, final_block);

#if HAVE_AES_NI
	//_mm_storeu_si128((__m128i*) output,       ctx->x2);
	//_mm_storeu_si128((__m128i*)(output + 16), ctx->x3);
#elif HAVE_AES_NEON
	//vst1q_u8(output,      ctx->x2);
	//vst1q_u8(output + 16, ctx->x3);
#endif
	memcpy(output, ctx->state, 32);
}

//>>>
static inline void vil_hash(const uint8_t*restrict data, uint64_t len, uint8_t output[32]) //<<<
{
	vil_context	ctx;

	vil_init(&ctx);
	vil_update(&ctx, data, len);
	vil_final(&ctx, output);
}

//>>>
//>>>

static OBJCMD(areion_perm256_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_BLOCK, A_objc};
	CHECK_ARGS_LABEL(finally, code, "block");

	int len;
	const uint8_t*	input = Tcl_GetBytesFromObj(interp, objv[A_BLOCK], &len);
	if (input == NULL) {code = TCL_ERROR; goto finally;}
	if (len != 32) THROW_ERROR_LABEL(finally, code, "block must be 32 bytes long");

	uint8_t	res[32];

#if HAVE_AES_NI
	__m128i	x0 = _mm_loadu_si128((__m128i*)(input));
	__m128i	x1 = _mm_loadu_si128((__m128i*)(input + 16));
	perm256(x0, x1);
	_mm_storeu_si128((__m128i*) res,       x0);
	_mm_storeu_si128((__m128i*)(res + 16), x1);
#elif HAVE_AES_NEON
	uint8x16_t	x0 = vld1q_u8(input);
	uint8x16_t	x1 = vld1q_u8(input + 16);
	perm256(x0, x1);
	vst1q_u8(res,      x0);
	vst1q_u8(res + 16, x1);
#else
	// Software fallback implementation
	uint8_t	x0[16], x1[16];
	memcpy(x0, input, 16);
	memcpy(x1, input + 16, 16);
	sw_perm256_x86_compatible(x0, x1);
	memcpy(res,      x0, 16);
	memcpy(res + 16, x1, 16);
#endif

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(res, 32));

finally:
	return code;
}

//>>>
static OBJCMD(areion_perm512_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_BLOCK, A_objc};
	CHECK_ARGS_LABEL(finally, code, "block");

	int len;
	const uint8_t*	input = Tcl_GetBytesFromObj(interp, objv[A_BLOCK], &len);
	if (input == NULL) {code = TCL_ERROR; goto finally;}
	if (len != 64) THROW_ERROR_LABEL(finally, code, "block must be 64 bytes long");

	uint8_t	res[64];

#if HAVE_AES_NI
	__m128i	x0 = _mm_loadu_si128((__m128i*)(input));
	__m128i	x1 = _mm_loadu_si128((__m128i*)(input + 16));
	__m128i	x2 = _mm_loadu_si128((__m128i*)(input + 32));
	__m128i	x3 = _mm_loadu_si128((__m128i*)(input + 48));

	__m128i	out[4];
	permute_areion_512(out, (__m128i[]){x0, x1, x2, x3});

	_mm_storeu_si128((__m128i*) res,       out[0]);
	_mm_storeu_si128((__m128i*)(res + 16), out[1]);
	_mm_storeu_si128((__m128i*)(res + 32), out[2]);
	_mm_storeu_si128((__m128i*)(res + 48), out[3]);
#elif HAVE_AES_NEON
	uint8x16_t	x0 = vld1q_u8(input);
	uint8x16_t	x1 = vld1q_u8(input + 16);
	uint8x16_t	x2 = vld1q_u8(input + 32);
	uint8x16_t	x3 = vld1q_u8(input + 48);
	perm512(x0, x1, x2, x3);
	vst1q_u8(res,      x3);
	vst1q_u8(res + 16, x0);
	vst1q_u8(res + 32, x1);
	vst1q_u8(res + 48, x2);
#else
	// Software fallback implementation
	permute_areion_512((uint8_t(*)[16])res, (const uint8_t(*)[16])input);
#endif

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(res, 64));

finally:
	return code;
}

//>>>
static OBJCMD(areion256_dm_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_BLOCK, A_objc};
	CHECK_ARGS_LABEL(finally, code, "block");

	int len;
	const uint8_t*	input = Tcl_GetBytesFromObj(interp, objv[A_BLOCK], &len);
	if (input == NULL) {code = TCL_ERROR; goto finally;}
	if (len != 32) THROW_ERROR_LABEL(finally, code, "block must be 32 bytes long");

	uint8_t	res[32];

#if HAVE_AES_NI
	__m128i	x0 = _mm_loadu_si128((__m128i*)(input));
	__m128i	x1 = _mm_loadu_si128((__m128i*)(input + 16));
	__m128i orig_x0 = x0;
	__m128i orig_x1 = x1;
	perm256(x0, x1);
	x0 = _mm_xor_si128(x0, orig_x0);
	x1 = _mm_xor_si128(x1, orig_x1);
	_mm_storeu_si128((__m128i*) res,       x0);
	_mm_storeu_si128((__m128i*)(res + 16), x1);
#elif HAVE_AES_NEON
	uint8x16_t	x0 = vld1q_u8(input);
	uint8x16_t	x1 = vld1q_u8(input + 16);
	uint8x16_t	orig_x0 = x0;
	uint8x16_t	orig_x1 = x1;
	perm256(x0, x1);
	x0 = veorq_u8(x0, orig_x0);
	x1 = veorq_u8(x1, orig_x1);
	vst1q_u8(res,      x0);
	vst1q_u8(res + 16, x1);
#else
	// Software fallback implementation
	uint8_t x0[16], x1[16];
	uint8_t orig_x0[16], orig_x1[16];

	memcpy(x0, input,      16);
	memcpy(x1, input + 16, 16);
	memcpy(orig_x0, x0, 16);
	memcpy(orig_x1, x1, 16);

	perm256(x0, x1);

	for (int i=0; i<16; i++) {
		x0[i] ^= orig_x0[i];
		x1[i] ^= orig_x1[i];
	}

	memcpy(res,      x0, 16);
	memcpy(res + 16, x1, 16);
#endif

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(res, 32));

finally:
	return code;
}

//>>>
static OBJCMD(areion512_dm_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_BLOCK, A_objc};
	CHECK_ARGS_LABEL(finally, code, "block");

	int len;
	const uint8_t*	input = Tcl_GetBytesFromObj(interp, objv[A_BLOCK], &len);
	if (input == NULL) {code = TCL_ERROR; goto finally;}
	if (len != 64) THROW_ERROR_LABEL(finally, code, "block must be 64 bytes long");

	uint8_t	tmp[64];

#if HAVE_AES_NI
	__m128i	x0 = _mm_loadu_si128((__m128i*)(input));
	__m128i	x1 = _mm_loadu_si128((__m128i*)(input + 16));
	__m128i	x2 = _mm_loadu_si128((__m128i*)(input + 32));
	__m128i	x3 = _mm_loadu_si128((__m128i*)(input + 48));
	__m128i orig_x0 = x0;
	__m128i orig_x1 = x1;
	__m128i orig_x2 = x2;
	__m128i orig_x3 = x3;

	__m128i	out[4];
	permute_areion_512(out, (__m128i[]){x0, x1, x2, x3});
	x0 = _mm_xor_si128(out[0], orig_x0);
	x1 = _mm_xor_si128(out[1], orig_x1);
	x2 = _mm_xor_si128(out[2], orig_x2);
	x3 = _mm_xor_si128(out[3], orig_x3);

	_mm_storeu_si128((__m128i*) tmp,       x0);
	_mm_storeu_si128((__m128i*)(tmp + 16), x1);
	_mm_storeu_si128((__m128i*)(tmp + 32), x2);
	_mm_storeu_si128((__m128i*)(tmp + 48), x3);
#elif HAVE_AES_NEON
	uint8x16_t	x0 = vld1q_u8(input);
	uint8x16_t	x1 = vld1q_u8(input + 16);
	uint8x16_t	x2 = vld1q_u8(input + 32);
	uint8x16_t	x3 = vld1q_u8(input + 48);
	uint8x16_t	orig_x0 = x0;
	uint8x16_t	orig_x1 = x1;
	uint8x16_t	orig_x2 = x2;
	uint8x16_t	orig_x3 = x3;

	perm512(x0, x1, x2, x3);
	// Match X86 exactly: permute_areion_512 reorders to {x3, x0, x1, x2} then XORs with original
	uint8x16_t perm_x0 = x0, perm_x1 = x1, perm_x2 = x2, perm_x3 = x3;
	x0 = veorq_u8(perm_x3, orig_x0);  // out[0] = x3_permuted XOR orig_x0
	x1 = veorq_u8(perm_x0, orig_x1);  // out[1] = x0_permuted XOR orig_x1
	x2 = veorq_u8(perm_x1, orig_x2);  // out[2] = x1_permuted XOR orig_x2
	x3 = veorq_u8(perm_x2, orig_x3);  // out[3] = x2_permuted XOR orig_x3
	vst1q_u8(tmp,      x0);
	vst1q_u8(tmp + 16, x1);
	vst1q_u8(tmp + 32, x2);
	vst1q_u8(tmp + 48, x3);
#else
	// Software fallback implementation
	uint8_t x0[16], x1[16], x2[16], x3[16];
	uint8_t orig_x0[16], orig_x1[16], orig_x2[16], orig_x3[16];

	memcpy(x0, input,      16);
	memcpy(x1, input + 16, 16);
	memcpy(x2, input + 32, 16);
	memcpy(x3, input + 48, 16);
	memcpy(orig_x0, x0, 16);
	memcpy(orig_x1, x1, 16);
	memcpy(orig_x2, x2, 16);
	memcpy(orig_x3, x3, 16);

	perm512(x0, x1, x2, x3);
	// Match X86 exactly: permute_areion_512 reorders to {x3, x0, x1, x2} then XORs with original
	uint8_t perm_x0[16], perm_x1[16], perm_x2[16], perm_x3[16];
	memcpy(perm_x0, x0, 16);
	memcpy(perm_x1, x1, 16);
	memcpy(perm_x2, x2, 16);
	memcpy(perm_x3, x3, 16);

	for (int i=0; i<16; i++) {
		x0[i] = perm_x3[i] ^ orig_x0[i];  // out[0] = x3_permuted XOR orig_x0
		x1[i] = perm_x0[i] ^ orig_x1[i];  // out[1] = x0_permuted XOR orig_x1  
		x2[i] = perm_x1[i] ^ orig_x2[i];  // out[2] = x1_permuted XOR orig_x2
		x3[i] = perm_x2[i] ^ orig_x3[i];  // out[3] = x2_permuted XOR orig_x3
	}

	memcpy(tmp,      x0, 16);
	memcpy(tmp + 16, x1, 16);
	memcpy(tmp + 32, x2, 16);
	memcpy(tmp + 48, x3, 16);
#endif

	uint8_t	res[32];
	aerion_trunc((const uint64_t*)tmp, (uint64_t*)res);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(res, 32));

finally:
	return code;
}

//>>>
static OBJCMD(areion512_md_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_BYTES, A_objc};
	CHECK_ARGS_LABEL(finally, code, "bytes");

	int len;
	const uint8_t*	input = Tcl_GetBytesFromObj(interp, objv[A_BYTES], &len);
	if (input == NULL) {code = TCL_ERROR; goto finally;}

	uint8_t	res[32];
	vil_hash(input, len, res);
	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(res, 32));

finally:
	return code;
}

//>>>

#if TESTMODE
static OBJCMD(areion_vlif_init_state_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_objc};
	CHECK_ARGS_LABEL(finally, code, "");

	vil_context	ctx;

	vil_init(&ctx);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(ctx.state, 32));

finally:
	return code;
}

//>>>
static OBJCMD(areion_nop_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_BYTES, A_objc};
	CHECK_ARGS_LABEL(finally, code, "bytes");

	int len;
	const uint8_t*	input = Tcl_GetBytesFromObj(interp, objv[A_BYTES], &len);
	if (input == NULL) {code = TCL_ERROR; goto finally;}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(input, len));

finally:
	return code;
}

//>>>
#endif

int areion_init(Tcl_Interp* interp) //<<<
{
	Tcl_CreateObjCommand(interp, NS "::areion_perm256",	areion_perm256_cmd,	NULL, NULL);
	Tcl_CreateObjCommand(interp, NS "::areion_perm512",	areion_perm512_cmd,	NULL, NULL);
	Tcl_CreateObjCommand(interp, NS "::areion256_dm",	areion256_dm_cmd,	NULL, NULL);
	Tcl_CreateObjCommand(interp, NS "::areion512_dm",	areion512_dm_cmd,	NULL, NULL);
	Tcl_CreateObjCommand(interp, NS "::areion512_md",	areion512_md_cmd,	NULL, NULL);

#if TESTMODE
	Tcl_CreateObjCommand(interp, NS "::_testmode_areion_vlif_init_state",	areion_vlif_init_state_cmd,	NULL, NULL);
	Tcl_CreateObjCommand(interp, NS "::_testmode_areion_nop",				areion_nop_cmd,				NULL, NULL);
#endif

	return TCL_OK;
}

//>>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4 noexpandtab
