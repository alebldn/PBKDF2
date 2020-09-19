#include "pbkdf2.h"

void pbkdf2(pbkdf2_ctx_t* ctx)
{
	uint64_t j;
	uint32_t U[W_PER_HASH];
	
    ctx->T[0] = 0;
    ctx->T[1] = 0;
    ctx->T[2] = 0;
    ctx->T[3] = 0;
    ctx->T[4] = 0;

    hmac_ctx_init(&ctx->hmac_ctx,
                  ctx->strlen_password * 8,
                  ctx->strlen_salt * 8 + 32 + BITS_PER_BLOCK);

    hmac_append_str_text(ctx, ctx->salt, ctx->strlen_salt);
    hmac_append_int_text(ctx, 1);

	for(j = 1; j <= ctx->iteration_count; j++)
	{
        hmac_append_str_key(ctx, ctx->password, ctx->strlen_password);
		hmac(&ctx->hmac_ctx);
		/*
		 * Ottimizzabile togliendo l'array U
		 */
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

		hmac_ctx_dispose(&ctx->hmac_ctx);
        hmac_ctx_init(&ctx->hmac_ctx,
                      BITS_PER_WORD * W_PER_HASH,
                      ctx->strlen_salt * 8 + 32);

		hmac_append_int_text(&ctx->hmac_ctx, U[0]);
        hmac_append_int_text(&ctx->hmac_ctx, U[1]);
        hmac_append_int_text(&ctx->hmac_ctx, U[2]);
        hmac_append_int_text(&ctx->hmac_ctx, U[3]);
        hmac_append_int_text(&ctx->hmac_ctx, U[4]);
	}
    hmac_ctx_dispose(&ctx->hmac_ctx);
}