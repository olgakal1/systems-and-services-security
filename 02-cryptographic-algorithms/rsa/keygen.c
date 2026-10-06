#include "keygen.h"
#include <time.h>
void keygen(mpz_t p, mpz_t q, mpz_t result[])
{
  // declaring variables suitable with gmp stdlib
  mpz_t delta, n, lamda;
  mpz_t epsilon[1];

  // initializing them
  mpz_inits(delta, n, lamda, epsilon[0], NULL);
  mpz_set_si(delta, 0);

  // calculating n using gmp library functions
  mpz_mul(n, p, q);     // n = p*q
  mpz_sub_ui(p, p, 1);  // p=(p-1)
  mpz_sub_ui(q, q, 1);  // q=(q-1)
  mpz_mul(lamda, p, q); // lamda(n)=(p-1)(q-1) euler's totient function

  epsilonGen(lamda, epsilon);

  mpz_invert(delta, epsilon[0], lamda);
  mpz_set(result[0], n);          // result[0]=n
  mpz_set(result[1], epsilon[0]); // result[1]=e
  mpz_set(result[2], delta);      // result[2]=d
  // gmp_printf("[DEBUG] delta = %Zd\n", delta);
  mpz_clears(delta, n, epsilon[0], lamda, NULL); // preventing memory leak
}

// given a key length this function generates key pair for RSA
void randomPair(mpz_t bitLength, mpz_t result[])
{
  // generate randomness!
  gmp_randstate_t state;
  mpz_t p, q, randomNum;
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, (unsigned int)time(NULL));
  mpz_inits(p, q, randomNum, NULL);

  mpz_urandomb(randomNum, state, mpz_get_ui(bitLength)); // generate odd number (p)
  mpz_nextprime(p, randomNum);
  mpz_urandomb(randomNum, state, mpz_get_ui(bitLength)); // generate odd number (q)
  mpz_nextprime(q, randomNum);
  keygen(p, q, result);

  // cleaning
  gmp_randclear(state);
  mpz_clears(p, q, randomNum, NULL);
  // result = [n, e, d]
}

// generates a random epsilon number where (e % lambda(n) != 0) AND (gcd(e, lambda) == 1)
void epsilonGen(mpz_t lamda, mpz_t result[])
{
  gmp_randstate_t state;
  mpz_t randomNum, e, gcdResult, modResult;
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, time(NULL));
  mpz_inits(randomNum, e, gcdResult, modResult, NULL);

  do
  {
    mpz_urandomb(randomNum, state, 256);
    mpz_nextprime(e, randomNum);
    mpz_gcd(gcdResult, e, lamda);
    mpz_mod(modResult, e, lamda);
  } while (!(mpz_cmp_si(modResult, 0) != 0 && mpz_cmp_si(gcdResult, 1) == 0));
  // gmp_printf("[DEBUG] epsilon: %Zd\n", index);

  mpz_set(result[0], e);
  mpz_clears(randomNum, e, gcdResult, modResult, NULL);
}