#include <iostream>

unsigned int rol(unsigned int x, int d) {
    return ((x << d) | x >> (32 - d)) & 0xffffffff;
}

int word_is_hex_ascii(unsigned int w) {
    return std::isxdigit(w & 0xff) && std::isxdigit((w >> 8) & 0xff) && std::isxdigit((w >> 16) & 0xff) && std::isxdigit((w >> 24) & 0xff);
}

int main(int argc, char** argv) {
    if(argc != 6) {
        exit(1);
    }

    unsigned int b1_ = std::stol(argv[1]);
    unsigned int o1 = std::stol(argv[2]);
    unsigned int o1_ = std::stol(argv[3]);
    unsigned int o2 = std::stol(argv[4]);
    unsigned int o2_ = std::stol(argv[5]);

    unsigned int y2, lhs, rhs, y1, k1, k6;
    unsigned int b1 = rol(b1_, 31);
    for(y2 = 0; y2 < 4294967295; y2++) {
        lhs = o1_ - o1;
        rhs = rol(b1_ ^ (y2 - o2 + o2_), 7) - rol(b1 ^ y2, 7);
        if(lhs == rhs) {
            y1 = rol(b1 ^ y2, 7);
            k1 = o1 - y1;
            k6 = o2 - y2;
            if(word_is_hex_ascii(k1) && word_is_hex_ascii(k6)) {
                std::cout << k1 << " " << k6 << std::endl;
            }
        }
    }
}
