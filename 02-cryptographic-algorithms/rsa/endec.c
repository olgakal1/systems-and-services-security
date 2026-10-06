#include "endec.h"

// insert a message (name of file), an encryption key [n, e] receive encrypted message (RSA)
// key[0] = n, key[1] = e
void encryptDataRSA(char *inputFile, char *outputFile, mpz_t key[])
{
    FILE *fp;
    FILE *output;
    int len = 0;
    char c;
    fp = fopen(inputFile, "r");
    output = fopen(outputFile, "w");
    // in case something goes wrong
    if (fp == NULL || output == NULL)
    {
        printf("File error!!!\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp); // length of file (bytes)
    fseek(fp, 0, SEEK_SET);
    mpz_t ciphChar, msgChar;
    mpz_inits(msgChar, ciphChar, NULL);
    int i = 0;
    while (i < len)
    {
        c = fgetc(fp);
        mpz_set_ui(msgChar, (unsigned int)c);
        mpz_powm(ciphChar, msgChar, key[1], key[0]); // m = c^e mod n
        gmp_fprintf(output, "%Zd", ciphChar);
        i++;
        if (i < len)
        {
            fprintf(output, "\n");
        }
    }
    // preventing memory leaks
    mpz_clears(msgChar, ciphChar, NULL);
    fclose(output);
    fclose(fp);
}

// key[0] = n, key[1] = d
void decryptDataRSA(char *inputFile, char *outputFile, mpz_t key[])
{
    FILE *fp;
    FILE *output;
    fp = fopen(inputFile, "r");
    output = fopen(outputFile, "w");
    // in case something goes wrong with files
    if (fp == NULL || output == NULL)
    {
        printf("File error!!!\n");
        return;
    }

    mpz_t ciphChar, msgChar;
    mpz_inits(ciphChar, msgChar, NULL);
    while (!feof(fp))
    {
        mpz_inp_str(ciphChar, fp, 10);
        mpz_powm(msgChar, ciphChar, key[1], key[0]); // m = c^d mod n
        gmp_fprintf(output, "%c", (char)mpz_get_ui(msgChar));
    }
    // preventing memory leaks
    mpz_clears(ciphChar, msgChar, NULL);
    fclose(fp);
    fclose(output);
}