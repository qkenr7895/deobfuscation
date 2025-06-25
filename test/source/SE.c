#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void trigger() {
    puts("target reached");
    abort();
}

uint32_t hex2u32(const char *hex8) {
    uint32_t v = 0;
    for (int i = 0; i < 8; i++) {
        char c = hex8[i];
        uint32_t d =
            ('0' <= c && c <= '9') ? c - '0' :
            ('a' <= c && c <= 'f') ? c - 'a' + 10 :
            ('A' <= c && c <= 'F') ? c - 'A' + 10 : 0xFF;
        if (d == 0xFF) { fputs("bad hex\n", stderr); exit(1); }
        v = (v << 4) | d;
    }
    return v;
}

int main(int argc, char **argv)
{
    if (argc != 2 || strlen(argv[1]) != 4) {
        fprintf(stderr, "usage: %s <4-char input>\n", argv[0]);
        return 1;
    }

    const unsigned char *s = (unsigned char *)argv[1];
    unsigned char a = s[0], b = s[1], c = s[2], d = s[3];

    // if (argc != 2) {
    //     fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
    //     return 1;
    // }

    // FILE *f = fopen(argv[1], "rb");
    // if (!f) {
    //     perror("fopen");
    //     return 1;
    // }

    // unsigned char s[4];
    // size_t len = fread(s, 1, 4, f);
    // fclose(f);

    // if (len != 4) {
    //     fprintf(stderr, "Input must be exactly 4 bytes\n");
    //     return 1;
    // }

    // unsigned char a = s[0], b = s[1], c = s[2], d = s[3];

    VMProtectBegin("Begin");
    if (a == 'C') {                               
        if ( ((b ^ c) + d) == 0x5A ) {              
            if ( ((b * d) & 0xFF) == 0x86 ) {         
                trigger();                         
            }
        }
    }
    VMProtectEnd();

    puts("safe");
    return 0;
}