#include <stdio.h>
#include <stdlib.h>

void func2() {
    __asm__ __volatile__ ("movaps %xmm3, %xmm3\n");
    __asm__ __volatile__ ("movaps %xmm3, %xmm3\n");
    __asm__ __volatile__ ("movaps %xmm3, %xmm3\n");
}

void func() {

    __asm__ __volatile__ ("movaps %xmm1, %xmm1\n");
    __asm__ __volatile__ ("movaps %xmm1, %xmm1\n");
    __asm__ __volatile__ ("movaps %xmm1, %xmm1\n");

    func2();
}

int main() {
    printf("before func\n");
    __asm__ __volatile__ ("movaps %xmm0, %xmm0\n");
    // VM Enter
    func();
    // VM Exit
   __asm__ __volatile__ ("movaps %xmm2, %xmm2\n");
    printf("after func\n");
}


