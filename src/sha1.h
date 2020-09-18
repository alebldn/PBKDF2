/*
 * sha1.h
 *
 *  Created on: Mar 5, 2020
 *      Author: Delta
 */
#ifndef SHA1_H_
#define SHA1_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>

/* Commentare la seguente riga quando non si e' in debug */
#define DEBUG

#define SHA1_COUNTER_INIT 	32
#define SHA1_WCOUNTER_INIT	0
#define SHA1_CCOUNTER_INIT 	0

#define BITS_PER_BLOCK		512
#define BITS_PER_WORD		32
#define W_PER_BLOCK 		16
#define W_PER_HASH			5

typedef enum
{
	false,
	true
} bit_t;

typedef struct
{
	uint32_t words[W_PER_BLOCK];
} chunk_t;

typedef struct
{
	chunk_t* 	chunks;
	uint32_t 	digest[W_PER_HASH];
	uint64_t 	num_of_chunks;
	uint64_t 	chunk_counter;
	uint8_t 	word_counter;
	uint8_t 	counter;
} sha1_ctx_t;

void sha1_append_bit(sha1_ctx_t* ctx, bit_t bit);
void sha1_append_char(sha1_ctx_t* ctx, char value);
void sha1_append_int(sha1_ctx_t* ctx, uint32_t value);
void sha1_append_long(sha1_ctx_t* ctx, uint64_t value);
void sha1_append_str(sha1_ctx_t* ctx, char* str, uint64_t strlen);
uint32_t rotate_left(const uint32_t value, int32_t shift);

void sha1(sha1_ctx_t* ctx);
void sha1_ctx_init(sha1_ctx_t* ctx, uint64_t num_of_chunks);
void sha1_ctx_finalize(sha1_ctx_t* ctx);
void sha1_ctx_dispose(sha1_ctx_t* ctx);
void sha1_pad(sha1_ctx_t* ctx);

#ifdef DEBUG
void print_chunks(sha1_ctx_t* ctx);
void print_digest(sha1_ctx_t* ctx);
#endif

#endif /* SHA1_H_ */
