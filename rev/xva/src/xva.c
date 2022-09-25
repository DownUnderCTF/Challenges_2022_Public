#include <stdio.h>
#include <unistd.h>
#include <immintrin.h>

#define ANS1 0x85765e6f
#define ANS2 0x7b761fa8
#define ANS3 0x05306ec9
#define ANS4 0xbd5d8cfa
#define ANS5 0xc2db0af6
#define ANS6 0x6cf52153
#define ANS7 0xabec2bcd
#define ANS8 0x5c211278

int check1(char* input) {
  int s = 0;
  short* input_ = (short*)input;
  s += input_[0];
  s += input_[1];
  s += input_[2];
  s += input_[3];
  s += input_[4];
  s += input_[5];
  s += input_[6];
  s += input_[7];
  s += input_[8];
  s += input_[9];
  s += input_[10];
  s += input_[11];
  s += input_[12];
  s += input_[13];
  s += input_[14];
  s += input_[15];
  return s == 384068;
}

int check2(char* input) {
  short* input_ = (short*)input;
  __m256i res;
  __m256i indexes1 = _mm256_set_epi32(1, 3, 4, 7, 6, 0, 1, 3);
  __m256i indexes2 = _mm256_set_epi32(5, 4, 7, 6, 2, 3, 0, 1);
  __m256i m_inp = _mm256_set_epi16(
      input_[0], input_[1], input_[2], input_[3], input_[4], input_[5], input_[6], input_[7],
      input_[8], input_[9], input_[10], input_[11], input_[12], input_[13], input_[14], input_[15]
  );

  __m256i a = _mm256_set1_epi16(0x419b);

  res = _mm256_add_epi16(m_inp, a);
  __m256i c = _mm256_permutevar8x32_epi32(res, indexes1);
  __m256i d = _mm256_permutevar8x32_epi32(res, indexes2);
  res = _mm256_mullo_epi16(res, d);
  res = _mm256_sub_epi16(res, c);

  unsigned int result[8];
  _mm256_storeu_si256((__m256i*)result, res);

  return (result[0] == ANS1 && result[1] == ANS2 && result[2] == ANS3 &&
  result[3] == ANS4 && result[4] == ANS5 && result[5] == ANS6 &&
  result[6] == ANS7 && result[7] == ANS8);
}

int main() {
  __m256i res;
  char input[32] = {0};

  read(0, input, 32);

  if(check1(input) && check2(input)) {
    ((char*)input)[32] = '\0';
    puts("Correct!");
  } else {
    puts("Wrong!");
  }
}
