#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <sodium.h>
#include <sys/resource.h>

void generateRSAKeyPair(mpz_t given_len);
void encrypt(char *input, char *output, char *keyf);
void decrypt(char *input, char *output, char *keyf);
int compute_sha256(const char *in_file, unsigned char *hash_output);
int sign(char *input, char *sign_out, char *keyf);
int verify(char *input, char *sign_in, char *keyf);
void performance(char *input, char *cipherTxt, char *decipherTxt);
void keyFile(char *fileName, mpz_t keys[]);
void print_help();
long get_peak_memory_kb();
