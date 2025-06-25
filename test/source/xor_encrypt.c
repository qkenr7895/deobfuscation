#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "VMProtect_SDK/include/VMProtectSDK.h"

int main() {
    uint8_t p[8], k[2], x[8], s[8];
    uint64_t encrypted = 0;

    uint64_t plain = 0x1122334455667788ULL;
    uint64_t key = 0x8943;

    __asm__ volatile ("pxor %%xmm1, %%xmm0" ::: "xmm3");
    VMProtectBegin("xor begin");

    for (int i = 0; i < 8; ++i)
        p[i] = (plain >> (i * 8)) & 0xFF;
    for (int i = 0; i < 2; ++i)
        k[i] = (key >> (i * 8)) & 0xFF;

    for (int i = 0; i < 8; ++i)
        x[i] = p[i] ^ k[i % 2];

    for (int i = 0; i < 8; ++i)
        s[i] = x[7 - i];

    for (int i = 0; i < 8; ++i)
        encrypted |= (uint64_t)s[i] << (i * 8);

    VMProtectEnd();
    __asm__ volatile ("pxor %%xmm3, %%xmm2" ::: "xmm0");

    printf("encrypted : %lx\n", encrypted);

    return 0;
}
