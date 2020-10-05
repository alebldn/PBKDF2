#include "src/pbkdf2.h"
#include <string.h>

/*     CHEATSHEET

Input:
        P =         password
        S =         salt
        c =         1
        Output =    0c60c80f 961f0e71 f3a9b524 af601206 2fe037a6

Input:
        P =         password
        S =         salt
        c =         2
        Output =    ea6c014d c72d6f8c cd1ed92a ce1d41f0 d8de8957

Input:
        P =         password
        S =         salt
        c =         4096
        Output =    4b007901 b765489a bead49d9 26f721d0 65a429c1

Input:
        P =         password
        S =         salt
        c =         16777216
        Output =    eefe3d61 cd4da4e4 e9945b3d 6ba2158c 2634e984

 */

int main(int argc, char** argv)
{
    char salt[MAX_LENGTH] = "salt";
    char password[MAX_LENGTH] = "password";

    uint32_t strlen_password, strlen_salt;
    uint32_t iteration_count = 4096;
    pbkdf2_ctx_t ctx;

    strlen_password = strlen(password);
    strlen_salt = strlen(salt);

    ctx.strlen_password = strlen_password;
    ctx.strlen_salt = strlen_salt;
    ctx.iteration_count = iteration_count;
    ctx.bits_in_result_hash = 256;

    strncpy((char*) ctx.password, password, ctx.strlen_password);
    strncpy((char*) ctx.salt, salt, ctx.strlen_salt);

    pbkdf2_ctx_init(&ctx);

    hmac_append_str_text(&ctx.hmac_ctx, ctx.salt, ctx.strlen_salt);
    hmac_append_str_key(&ctx.hmac_ctx, ctx.password, ctx.strlen_password);

    pbkdf2(&ctx);

    for(int i = 0; i < ctx.bits_in_result_hash / BITS_IN_WORD; i++)
    {
        printf("%08x ", ctx.T[i]);
    }
    printf("\n");

    pbkdf2_ctx_dispose(&ctx);

}
