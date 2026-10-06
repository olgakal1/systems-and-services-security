
#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>

void encryptDataRSA(char *input_file, char *output_file, mpz_t key[]);
void decryptDataRSA(char *input_file, char *output_file, mpz_t key[]);
