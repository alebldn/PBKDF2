#include "pbkdf2.h"

void pbkdf2_append_bit_password(pbkdf2_ctx_t* ctx, bit_t value)
{
	hmac_append_bit_key(&ctx->hmac_ctx, value);
}

void pbkdf2_append_bit_salt(pbkdf2_ctx_t* ctx, bit_t value)
{
	hmac_append_bit_text(&ctx->hmac_ctx, value);
}

void pbkdf2_append_char_password(pbkdf2_ctx_t* ctx, char value)
{
	hmac_append_char_key(&ctx->hmac_ctx, value);
}

void pbkdf2_append_char_salt(pbkdf2_ctx_t* ctx, char value)
{
	hmac_append_char_text(&ctx->hmac_ctx, value);
}

void pbkdf2_append_str_password(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen)
{
	hmac_append_str_key(&ctx->hmac_ctx, value, strlen);
}

void pbkdf2_append_str_salt(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen)
{
	hmac_append_str_text(&ctx->hmac_ctx, value, strlen);
}

void pbkdf2_append_int_password(pbkdf2_ctx_t* ctx, uint32_t value)
{
	hmac_append_int_key(&ctx->hmac_ctx, value);
}

void pbkdf2_append_int_salt(pbkdf2_ctx_t* ctx, uint32_t value)
{
	hmac_append_int_text(&ctx->hmac_ctx, value);
}

void pbkdf2_append_long_password(pbkdf2_ctx_t* ctx, uint64_t value)
{
	hmac_append_int_key(&ctx->hmac_ctx, value);
}

void pbkdf2_append_long_salt(pbkdf2_ctx_t* ctx, uint64_t value)
{
	hmac_append_int_text(&ctx->hmac_ctx, value);
}

void pbkdf2_ctx_init(pbkdf2_ctx_t* ctx,	uint64_t bits_to_be_written_in_password, uint64_t bits_to_be_written_in_salt)
{
	hmac_ctx_init(&ctx->hmac_ctx, bits_to_be_written_in_password, bits_to_be_written_in_salt + 32);

	ctx->T[0] = 0;
	ctx->T[1] = 0;
	ctx->T[2] = 0;
	ctx->T[3] = 0;
	ctx->T[4] = 0;
}

void pbkdf2_ctx_dispose(pbkdf2_ctx_t* ctx)
{
	hmac_ctx_dispose(&ctx->hmac_ctx);
}

/*
 * Versione ridotta di pbkdf2 in quanto l'algoritmo di hashing � hardcoded
 * -----------------------------------------------------------------------
 * Diamo per scontato chesiano gi� inizializzate le strutture dati di Password e Salt all'interno di ctx
 * HMAC(key, text)
 * -----------------------------------------------------------------------------------------------------
 * pseudocode:
 * Input:
 * 		P Password
 * 		S Salt
 * 		C Iteration count
 * 		kLen Length of MK in bits; at most (2^32-1) * hLen
 *
 * Parameter:
 * 		PRF HMAC with an approved hash function
 * 		hlen Digest size of the hash function
 * 		Output: mk Master key
 *
 * Algorithm:
 * 		If (kLen > (2^32-1) * hLen)
 * 			Return an error indicator and stop ;
 * 		len = ceil(kLen / hLen);
 * 		r = kLen � (len � 1) * hLen ;
 * 		For i = 1 to len
 * 			Ti = 0;
 * 			U0 = S || Int(i);
 * 			For j = 1 to C
 * 				Uj= HMAC(P, Uj-1)
 * 				Ti = Ti xor Uj
 * 		Return mk = T1 || T2 || � || Tlen <0�r-1>
 */

void pbkdf2(pbkdf2_ctx_t* ctx)
{
	uint64_t j;
	uint32_t U[W_PER_HASH];
/*
 * for(i = 1 to len) (len = 1)
 */
	pbkdf2_append_int_salt(ctx, 1);
	for(j = 1; j <= ctx->iteration_count; j++)
	{
		hmac(&ctx->hmac_ctx);
		U[0] = ctx->hmac_ctx.digest[0];
		U[1] = ctx->hmac_ctx.digest[1];
		U[2] = ctx->hmac_ctx.digest[2];
		U[3] = ctx->hmac_ctx.digest[3];
		U[4] = ctx->hmac_ctx.digest[4];

		ctx->T[0] = ctx->T[0] ^ U[0];
		ctx->T[1] = ctx->T[1] ^ U[1];
		ctx->T[2] = ctx->T[2] ^ U[2];
		ctx->T[3] = ctx->T[3] ^ U[3];
		ctx->T[4] = ctx->T[4] ^ U[4];

		hmac_ctx_key_dispose(&ctx->hmac_ctx);
		hmac_ctx_key_init(&ctx->hmac_ctx, BITS_PER_WORD * W_PER_HASH);
		hmac_ctx_reset(&ctx->hmac_ctx);

		hmac_append_int_key(&ctx->hmac_ctx, U[0]);
		hmac_append_int_key(&ctx->hmac_ctx, U[1]);
		hmac_append_int_key(&ctx->hmac_ctx, U[2]);
		hmac_append_int_key(&ctx->hmac_ctx, U[3]);
		hmac_append_int_key(&ctx->hmac_ctx, U[4]);
	}
}