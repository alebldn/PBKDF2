/*
 * hmac_sha1.h
 *
 *  Created on: Mar 12, 2020
 *      Author: Delta
 */

#ifndef HMAC_H_
#define HMAC_H_

#include "sha1.h"

typedef struct
{
	sha1_ctx_t sha1_ctx_text;
	sha1_ctx_t sha1_ctx_key;
	chunk_t outer_pad;
	chunk_t inner_pad;
	uint32_t digest[W_PER_HASH];

} hmac_ctx_t;

void hmac_append_bit_key(hmac_ctx_t* ctx, bit_t value);
void hmac_append_bit_text(hmac_ctx_t* ctx, bit_t value);
void hmac_append_char_key(hmac_ctx_t* ctx, char value);
void hmac_append_char_text(hmac_ctx_t* ctx, char value);
void hmac_append_str_key(hmac_ctx_t* ctx, char* value, uint64_t strlen);
void hmac_append_str_text(hmac_ctx_t* ctx, char* value, uint64_t strlen);
void hmac_append_int_key(hmac_ctx_t* ctx, uint32_t value);
void hmac_append_int_text(hmac_ctx_t* ctx, uint32_t value);
void hmac_append_long_key(hmac_ctx_t* ctx, uint64_t value);
void hmac_append_long_text(hmac_ctx_t* ctx, uint64_t value);

void hmac_pad(sha1_ctx_t* ctx);
void hmac_ctx_init(hmac_ctx_t* ctx, uint64_t bytes_to_be_written_in_key, uint64_t bytes_to_be_written_in_text);
void hmac_ctx_reset(hmac_ctx_t* ctx);
void hmac_ctx_key_init(hmac_ctx_t* ctx, uint64_t bits_to_be_written_in_key);
void hmac_ctx_text_init(hmac_ctx_t* ctx, uint64_t bits_to_be_written_in_text);
void hmac_ctx_dispose(hmac_ctx_t* ctx);
void hmac_ctx_key_dispose(hmac_ctx_t* ctx);
void hmac_ctx_text_dispose(hmac_ctx_t* ctx);


void hmac(hmac_ctx_t* ctx);

#endif /* HMAC_H_ */
