#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

void keygen(mpz_t p, mpz_t q, mpz_t result[]); // generating RSA key-pair
void epsilonGen(mpz_t lamda, mpz_t result[]);  // generating RSA encryption key
void randomPair(mpz_t bitLength, mpz_t result[]);