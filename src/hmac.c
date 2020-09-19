/*
 * hmac_sha1.c
 *
 *  Created on: Mar 6, 2020
 *      Author: Delta
 */

#include "hmac.h"

void hmac_append_bit_key(hmac_ctx_t* ctx, bit_t value)
{
	sha1_append_bit(&ctx->sha1_ctx_key, value);
}

void hmac_append_bit_text(hmac_ctx_t* ctx, bit_t value)
{
	sha1_append_bit(&ctx->sha1_ctx_text, value);
}

void hmac_append_char_key(hmac_ctx_t* ctx, char value)
{
	sha1_append_char(&ctx->sha1_ctx_key, value);
}

void hmac_append_char_text(hmac_ctx_t* ctx, char value)
{
	sha1_append_char(&ctx->sha1_ctx_text, value);
}

void hmac_append_str_key(hmac_ctx_t* ctx, char* value, uint64_t strlen)
{
	sha1_append_str(&ctx->sha1_ctx_key, value, strlen);
}

void hmac_append_str_text(hmac_ctx_t* ctx, char* value, uint64_t strlen)
{
	sha1_append_str(&ctx->sha1_ctx_text, value, strlen);
}

void hmac_append_int_key(hmac_ctx_t* ctx, uint32_t value)
{
	sha1_append_int(&ctx->sha1_ctx_key, value);
}

void hmac_append_int_text(hmac_ctx_t* ctx, uint32_t value)
{
	sha1_append_int(&ctx->sha1_ctx_text, value);
}

void hmac_append_long_key(hmac_ctx_t* ctx, uint64_t value)
{
	sha1_append_long(&ctx->sha1_ctx_key, value);
}

void hmac_append_long_text(hmac_ctx_t* ctx, uint64_t value)
{
	sha1_append_long(&ctx->sha1_ctx_text, value);
}

void hmac_pad(sha1_ctx_t* ctx)
{
	uint64_t cap = BITS_PER_BLOCK - (ctx->word_counter*SHA1_COUNTER_INIT + (32 - ctx->counter));

#ifdef DEBUG
	assert(cap > 0);
	assert(ctx->num_of_chunks > 0);
	assert(ctx->chunks != NULL);
#endif
	for(uint32_t i = 0; i < cap; i++)
	{
		sha1_append_bit(ctx, 0);
	}
}

void hmac_ctx_key_init(hmac_ctx_t* ctx, uint64_t bits_to_be_written_in_key)
{
	sha1_ctx_init(&ctx->sha1_ctx_key, (bits_to_be_written_in_key + 1 + 64) / BITS_PER_BLOCK + 1);
}

void hmac_ctx_text_init(hmac_ctx_t* ctx, uint64_t bits_to_be_written_in_text)
{
	sha1_ctx_init(&ctx->sha1_ctx_text, (bits_to_be_written_in_text + 1 + 64) / BITS_PER_BLOCK + 1 + 1);
	ctx->sha1_ctx_text.chunk_counter += 1;
}

void hmac_ctx_reset(hmac_ctx_t* ctx)
{
	ctx->inner_pad.words[ 0] = 0;
	ctx->inner_pad.words[ 1] = 0;
	ctx->inner_pad.words[ 2] = 0;
	ctx->inner_pad.words[ 3] = 0;
	ctx->inner_pad.words[ 4] = 0;
	ctx->inner_pad.words[ 5] = 0;
	ctx->inner_pad.words[ 6] = 0;
	ctx->inner_pad.words[ 7] = 0;
	ctx->inner_pad.words[ 8] = 0;
	ctx->inner_pad.words[ 9] = 0;
	ctx->inner_pad.words[10] = 0;
	ctx->inner_pad.words[11] = 0;
	ctx->inner_pad.words[12] = 0;
	ctx->inner_pad.words[13] = 0;
	ctx->inner_pad.words[14] = 0;
	ctx->inner_pad.words[15] = 0;

	ctx->outer_pad.words[ 0] = 0;
	ctx->outer_pad.words[ 1] = 0;
	ctx->outer_pad.words[ 2] = 0;
	ctx->outer_pad.words[ 3] = 0;
	ctx->outer_pad.words[ 4] = 0;
	ctx->outer_pad.words[ 5] = 0;
	ctx->outer_pad.words[ 6] = 0;
	ctx->outer_pad.words[ 7] = 0;
	ctx->outer_pad.words[ 8] = 0;
	ctx->outer_pad.words[ 9] = 0;
	ctx->outer_pad.words[10] = 0;
	ctx->outer_pad.words[11] = 0;
	ctx->outer_pad.words[12] = 0;
	ctx->outer_pad.words[13] = 0;
	ctx->outer_pad.words[14] = 0;
	ctx->outer_pad.words[15] = 0;

	ctx->digest[0] = 0;
	ctx->digest[1] = 0;
	ctx->digest[2] = 0;
	ctx->digest[3] = 0;
	ctx->digest[4] = 0;
}

void hmac_ctx_init(hmac_ctx_t* ctx, uint64_t bits_to_be_written_in_key, uint64_t bits_to_be_written_in_text)
{
	hmac_ctx_key_init(ctx, bits_to_be_written_in_key);
	hmac_ctx_text_init(ctx, bits_to_be_written_in_text);
	hmac_ctx_reset(ctx);
}

void hmac_ctx_key_dispose(hmac_ctx_t* ctx)
{
	sha1_ctx_dispose(&ctx->sha1_ctx_key);
}

void hmac_ctx_text_dispose(hmac_ctx_t* ctx)
{
	sha1_ctx_dispose(&ctx->sha1_ctx_text);
}

void hmac_ctx_dispose(hmac_ctx_t* ctx)
{
	hmac_ctx_text_dispose(ctx);
	hmac_ctx_key_dispose(ctx);
}

void hmac(hmac_ctx_t* ctx)
{
	uint32_t i;
	uint8_t temp_counter, temp_word_counter;
	uint64_t temp_chunk_counter;
	uint64_t bits_written_in_key, bits_written_in_text;

	bits_written_in_key = ctx->sha1_ctx_key.chunk_counter*BITS_PER_BLOCK
			+ ctx->sha1_ctx_key.word_counter*BITS_PER_WORD
			+ 32 - ctx->sha1_ctx_key.counter;

    bits_written_in_text = ctx->sha1_ctx_text.chunk_counter*BITS_PER_BLOCK
                          + ctx->sha1_ctx_text.word_counter*BITS_PER_WORD
                          + 32 - ctx->sha1_ctx_text.counter;

	if(bits_written_in_key > BITS_PER_BLOCK)
	{
		sha1(&ctx->sha1_ctx_key);

		sha1_ctx_dispose(&ctx->sha1_ctx_key);
		sha1_ctx_init(&ctx->sha1_ctx_key, 1);

		sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[0]);
		sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[1]);
		sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[2]);
		sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[3]);
		sha1_append_int(&ctx->sha1_ctx_key, ctx->sha1_ctx_key.digest[4]);
	}
	/**
	 * potrebbe essere tolto dal momento in cui tutte le word sono inizializzate a 0
	 * Ma dovrebbe essere sostituito in maniera tale da aggiornare i counter in maniera corretta.
	 */
	hmac_pad(&ctx->sha1_ctx_key);

	for(i = 0; i < W_PER_BLOCK; i++)
	{
		ctx->outer_pad.words[i] = ctx->sha1_ctx_key.chunks[0].words[i] ^ 0x5C5C5C5C;
		ctx->inner_pad.words[i] = ctx->sha1_ctx_key.chunks[0].words[i] ^ 0x36363636;
	}

	/**
	 * Il primo chunk e' sempre o o_pad o i_pad, quindi e' necessario contare un chunk in piu'
	 * rispetto a quelli necessari per contenere text
	 */
	sha1_ctx_dispose(&ctx->sha1_ctx_key);

	temp_counter = ctx->sha1_ctx_text.counter;
	temp_word_counter = ctx->sha1_ctx_text.word_counter;
	temp_chunk_counter = ctx->sha1_ctx_text.chunk_counter;

	ctx->sha1_ctx_text.counter = SHA1_COUNTER_INIT;
	ctx->sha1_ctx_text.word_counter = SHA1_WCOUNTER_INIT;
	ctx->sha1_ctx_text.chunk_counter = SHA1_CCOUNTER_INIT;

	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 0]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 1]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 2]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 3]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 4]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 5]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 6]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 7]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 8]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[ 9]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[10]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[11]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[12]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[13]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[14]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->inner_pad.words[15]);

	ctx->sha1_ctx_text.num_of_chunks = bits_written_in_text / BITS_PER_BLOCK + 1;
    ctx->sha1_ctx_text.counter = temp_counter;
	ctx->sha1_ctx_text.word_counter = temp_word_counter;
	ctx->sha1_ctx_text.chunk_counter = temp_chunk_counter;

	sha1_ctx_finalize(&ctx->sha1_ctx_text);
	sha1(&ctx->sha1_ctx_text);

	ctx->digest[0] = ctx->sha1_ctx_text.digest[0];
	ctx->digest[1] = ctx->sha1_ctx_text.digest[1];
	ctx->digest[2] = ctx->sha1_ctx_text.digest[2];
	ctx->digest[3] = ctx->sha1_ctx_text.digest[3];
	ctx->digest[4] = ctx->sha1_ctx_text.digest[4];

	sha1_ctx_dispose(&ctx->sha1_ctx_text);
	/**
	 * Il problema sta qui
	 */
	sha1_ctx_init(&ctx->sha1_ctx_text, 2);
    /**                                             ^
    *                                               |
    */
    sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 0]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 1]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 2]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 3]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 4]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 5]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 6]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 7]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 8]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[ 9]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[10]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[11]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[12]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[13]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[14]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->outer_pad.words[15]);

	sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[0]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[1]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[2]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[3]);
	sha1_append_int(&ctx->sha1_ctx_text, ctx->digest[4]);

	sha1_ctx_finalize(&ctx->sha1_ctx_text);
	sha1(&ctx->sha1_ctx_text);

	ctx->digest[0] = ctx->sha1_ctx_text.digest[0];
	ctx->digest[1] = ctx->sha1_ctx_text.digest[1];
	ctx->digest[2] = ctx->sha1_ctx_text.digest[2];
	ctx->digest[3] = ctx->sha1_ctx_text.digest[3];
	ctx->digest[4] = ctx->sha1_ctx_text.digest[4];
}
/*
int main()
{
	char key[] = "key";
	char text[] = "The quick brown fox jumps over the lazy dog";
	hmac_ctx_t ctx;

	hmac_ctx_reset(&ctx);
	hmac_ctx_key_init(&ctx, strlen(key) * 8);
	hmac_ctx_text_init(&ctx, strlen(text) * 8);

	for(uint32_t i = 0; i < strlen(key); i++)
			hmac_append_char_key(&ctx, key[i]);

	for(uint32_t i = 0; i < strlen(text); i++)
		hmac_append_char_text(&ctx, text[i]);

	hmac(&ctx);

	hmac_ctx_dispose(&ctx);
	//hmac("key", "The quick brown fox jumps over the lazy dog") = de7c9b85 b8b78aa6 bc8a7a36 f70a9070 1c9db4d9
}
*/
