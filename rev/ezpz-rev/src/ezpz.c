// gcc -o ezpz ezpz.c -no-pie -fno-stack-protector -O1

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define N 14
#define NN 196
#define BOARD_DATA "5a4b3c2d5a4b4c1d2a1e3a3b4c1d2a1e1f2a3b3c1g1d3e5f1b2c2g1d1f2e4f6g1d7f3h3g1d4f6h3g1d2f1i4j1h2k2l1m1d3i2j5k2l2m2i3j4k3l2m2i3j4k3l2m1i5j2k2n2l2m1i4j5n4l"

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

char* expand_board(char* board) {
    char* expanded = (char*) malloc(NN);

    int i = 0;
    while(*board) {
        int n = *board - '0';
        char c = *(board + 1);
        for(int j = 0; j < n; j++) {
            expanded[i++] = c;
        }
        board += 2;
    }

    return expanded;
}

// Check that there are 3 1's in each row
int check1(char* board, char* inp) {
    for(int i = 0; i < N; i++) {
        int count = 0;
        for(int j = 0; j < N; j++) {
            count += inp[N * i + j] == '1';
        }
        if(count != 3) {
            return 0;
        }
    }
    return 1;
}

// Check that there are 3 1's in each column
int check2(char* board, char* inp) {
    for(int i = 0; i < N; i++) {
        int count = 0;
        for(int j = 0; j < N; j++) {
            count += inp[N * j + i] == '1';
        }
        if(count != 3) {
            return 0;
        }
    }
    return 1;
}

// Check that there are 3 1's in each area
int check3(char* board, char* inp) {
    int counts[N];
    int k;
    for(k = 0; k < N; k++) {
        counts[k] = 0;
    }
    for(int i = 0; i < N; i++) {
        for(int j = 0; j < N; j++) {
            int idx = N * i + j;
            if(inp[idx] == '1') {
                counts[board[idx] - 'a']++;
            }
        }
    }
    for(k = 0; k < N; k++) {
        if(counts[k] != 3) {
            return 0;
        }
    }
    return 1;
}

// Check that no 1's are adjacent
int check4(char* board, char* inp) {
    for(int i = 0; i < N; i++) {
        for(int j = 0; j < N; j++) {
            int idx = N * i + j;
            if(inp[idx] == '1') {
                int d_neighbours[] = {-1, -N-1, -N, -N+1, 1, N+1, N, N-1};
                for(int k = 0; k < 8; k++) {
                    int d = d_neighbours[k];
                    if(j == 0 && (d == -1 || d == -N-1 || d == N-1)) continue;
                    if(j == N-1 && (d == 1 || d == -N+1 || d == N+1)) continue;
                    if(idx + d < 0 || idx + d >= NN) continue;
                    if(inp[idx + d] == '1') {
                        return 0;
                    }
                }
            }
        }
    }
    return 1;
}

int main() {
    init();

    char inp[NN];
    char* board = expand_board(BOARD_DATA);

    gets(inp);

    if(check1(board, inp) && check2(board, inp) && check3(board, inp) && check4(board, inp)) {
        int fd = open("flag-rev.txt", O_RDONLY);
        char flag[0x100];
        read(fd, flag, 0x100);
        puts(flag);
    } else {
        puts("Incorrect!");
        exit(1);
    }

    return 0;
}
