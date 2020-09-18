/*
 * pbkdf2_hmac_sha1.h
 *
 *  Created on: Mar 27, 2020
 *      Author: Delta
 */

#ifndef PBKDF2_H_
#define PBKDF2_H_

#include "hmac.h"

typedef struct
{
	hmac_ctx_t hmac_ctx;
	uint64_t iteration_count;
	uint32_t T[W_PER_HASH];
} pbkdf2_ctx_t;

void pbkdf2_append_bit_password(pbkdf2_ctx_t* ctx, bit_t value);
void pbkdf2_append_bit_salt(pbkdf2_ctx_t* ctx, bit_t value);
void pbkdf2_append_char_password(pbkdf2_ctx_t* ctx, char value);
void pbkdf2_append_char_salt(pbkdf2_ctx_t* ctx, char value);
void pbkdf2_append_str_password(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen);
void pbkdf2_append_str_salt(pbkdf2_ctx_t* ctx, char* value, uint64_t strlen);
void pbkdf2_append_int_password(pbkdf2_ctx_t* ctx, uint32_t value);
void pbkdf2_append_int_salt(pbkdf2_ctx_t* ctx, uint32_t value);
void pbkdf2_append_long_password(pbkdf2_ctx_t* ctx, uint64_t value);
void pbkdf2_append_long_salt(pbkdf2_ctx_t* ctx, uint64_t value);

void pbkdf2_ctx_init(pbkdf2_ctx_t* ctx,	uint64_t bits_to_be_written_in_password, uint64_t bits_to_be_written_in_salt);
void pbkdf2_ctx_dispose(pbkdf2_ctx_t* ctx);
void pbkdf2(pbkdf2_ctx_t* ctx);

#endif /* PBKDF2_H_ */
