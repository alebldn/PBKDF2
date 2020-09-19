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
	char* password;
	char* salt;
	uint32_t strlen_password;
	uint32_t strlen_salt;
	uint64_t iteration_count;
	uint32_t T[W_PER_HASH];

} pbkdf2_ctx_t;

void pbkdf2(pbkdf2_ctx_t* ctx);

#endif /* PBKDF2_H_ */
