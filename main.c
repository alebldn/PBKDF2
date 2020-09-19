#include "src/pbkdf2.h"

/*
 * CHEATSHEET

Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 1
       dkLen = 20
Output:
       DK = 0c 60 c8 0f 96 1f 0e 71
            f3 a9 b5 24 af 60 12 06
            2f e0 37 a6


Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 2
       dkLen = 20
Output:
       DK = ea 6c 01 4d c7 2d 6f 8c
            cd 1e d9 2a ce 1d 41 f0
            d8 de 89 57


Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 4096
       dkLen = 20
Output:
       DK = 4b 00 79 01 b7 65 48 9a
            be ad 49 d9 26 f7 21 d0
            65 a4 29 c1


Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 16777216
       dkLen = 20
Output:
       DK = ee fe 3d 61 cd 4d a4 e4
            e9 94 5b 3d 6b a2 15 8c
            26 34 e9 84

 */

int main(int argc, char** argv)
{
    char salt[] = "salt";
    char password[] = "password";
    int iteration_count = 2;

    pbkdf2_ctx_t ctx;
    ctx.iteration_count = iteration_count;

    ctx.strlen_password = strlen(password);
    ctx.strlen_salt = strlen(salt);

    ctx.password = (char*) malloc(ctx.strlen_password * sizeof(char));
    ctx.salt = (char*) malloc(ctx.strlen_salt * sizeof(char));

    strncpy(ctx.password, password, ctx.strlen_password);
    strncpy(ctx.salt, salt, ctx.strlen_salt);

    pbkdf2(&ctx);

    printf("%08x %08x %08x %08x %08x\n", ctx.T[0], ctx.T[1], ctx.T[2], ctx.T[3], ctx.T[4]);
    free(ctx.password);
    free(ctx.salt);
}
