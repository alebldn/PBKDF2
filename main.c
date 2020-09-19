#include "src/pbkdf2.h"

int main(int argc, char** argv)
{
    pbkdf2_ctx_t ctx;
    char password[] = "password";
    char salt[] = "salt";
    uint64_t iteration_count = 2;
    uint32_t strlen_password, strlen_salt;

    strlen_password = strlen(password);
    strlen_salt = strlen(salt);

    pbkdf2_ctx_init(&ctx, strlen_password * 8, strlen_salt * 8);
    ctx.iteration_count = iteration_count;
    pbkdf2_append_str_password(&ctx, password, strlen_password);       // TEXT
    pbkdf2_append_str_salt(&ctx, salt, strlen_salt);                // KEY
    pbkdf2(&ctx);

    printf("%08x %08x %08x %08x %08x\n", ctx.T[0], ctx.T[1], ctx.T[2], ctx.T[3], ctx.T[4]);
}
