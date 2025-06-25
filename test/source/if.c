#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "VMProtect_SDK/include/VMProtectSDK.h"

int main() {
    uint64_t rax, rbx, result;
    rax = 0x11223344;
    rbx = 0x55556666;
    result = 0x88889999;

    __asm__ volatile ("pxor %%xmm1, %%xmm0" ::: "xmm3");
    VMProtectBegin("xor begin");

    result /= rax;

    VMProtectEnd();
    __asm__ volatile ("pxor %%xmm3, %%xmm2" ::: "xmm0");

    printf("result : %lx\n", result);

    return 0;
}
