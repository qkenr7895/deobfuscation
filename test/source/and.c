#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "VMProtect_SDK/include/VMProtectSDK.h"

int main() {
    uint64_t a, b, result;

    a = 0x11223344;
    b = 0x55667788;

    __asm__ volatile ("pxor %%xmm1, %%xmm0" ::: "xmm3");

    /* VMProtect 보호 구간 */
    VMProtectBegin("xor begin");

    /* ────────── 난독화 블록 ────────── */

    /* 1) 노이즈 (결국 0이 됨) */
    uint64_t noise = ((a << 3) + (b >> 4)) ^ 0xCAFEBABEDEADBEEFULL;
    noise ^= noise; // 0으로 만듦

    /* 2) (a|b), (a&b)에 마스크를 씌웠다가 해제 → 원래 값 복원 */
    uint64_t part_or   = (a | b) ^ 0xAAAAAAAAAAAAAAAAULL;
    part_or           ^= 0xAAAAAAAAAAAAAAAAULL; // 다시 복구 → (a | b)

    uint64_t part_and  = (a & b) ^ 0x5555555555555555ULL;
    part_and          ^= 0x5555555555555555ULL; // 복구 → (a & b)

    /* 3) (a|b) - (a&b) == a^b (unsigned 64-bit에서 유효) */
    result = part_or - part_and + noise;

    /* ────────── 난독화 블록 끝 ────────── */
    VMProtectEnd();

    __asm__ volatile ("pxor %%xmm3, %%xmm2" ::: "xmm0");

    printf("a opertation b : 0x%lx\n", result);   /* 항상 a ^ b */

    return 0;
}