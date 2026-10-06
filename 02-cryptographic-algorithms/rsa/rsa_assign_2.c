#include "rsa_assign_2.h"
#include "endec.h"
#include "keygen.h"
#include <time.h>
#define DEFAULTLEN 256

void encrypt(char *input, char *output, char *keyf)
{
    mpz_t keys[2];
    keyFile(keyf, keys);

    encryptDataRSA(input, output, keys);

    mpz_clears(keys[0], keys[1], NULL);
}

void decrypt(char *input, char *output, char *keyf)
{
    mpz_t keys[2];
    keyFile(keyf, keys);
    decryptDataRSA(input, output, keys);

    mpz_clears(keys[0], keys[1], NULL);
}

// reads key pair from file stores them into keys array
void keyFile(char *fileName, mpz_t keys[])
{
    double cpu_time_used;
    FILE *fp;
    fp = fopen(fileName, "r");
    if (fp == NULL)
        return;
    mpz_inits(keys[0], keys[1], NULL);

    mpz_inp_str(keys[0], fp, 10);
    mpz_inp_str(keys[1], fp, 10);
    fclose(fp);
}

// generate RSA key pair to specific files
void generateRSAKeyPair(mpz_t given_len)
{
    mpz_t real_len, temp;
    mpz_inits(real_len, temp, NULL);
    mpz_set_ui(temp, 2);
    mpz_cdiv_q(real_len, given_len, temp); // real_len = len / 2
    mpz_clear(temp);

    mpz_t key[3];
    mpz_inits(key[0], key[1], key[2], NULL);
    randomPair(real_len, key);

    printf("Generating key...\n");

    char *len_str = mpz_get_str(NULL, 10, given_len);
    char *public = (char *)malloc(strlen("public_") + strlen(len_str) + strlen(".key") + 1);
    char *private = (char *)malloc(strlen("private_") + strlen(len_str) + strlen(".key") + 1);

    // Copy the components into the result string
    strcpy(public, "public_");
    strcat(public, len_str);
    strcat(public, ".key");

    strcpy(private, "private_");
    strcat(private, len_str);
    strcat(private, ".key");

    FILE *public_file;
    FILE *private_file;
    public_file = fopen(public, "w");
    private_file = fopen(private, "w");

    randomPair(real_len, key);
    gmp_fprintf(public_file, "%Zd\n", key[0]);
    gmp_fprintf(public_file, "%Zd", key[1]); // write n, e
    gmp_fprintf(private_file, "%Zd\n", key[0]);
    gmp_fprintf(private_file, "%Zd", key[2]); // write n, d

    free(len_str);
    free(public);
    free(private);
    fclose(public_file);
    fclose(private_file);

    mpz_clears(key[0], key[1], key[2], real_len, NULL);
}

int compute_sha256(const char *in_file, unsigned char *hash_output)
{
    if (sodium_init() < 0)
    {
        fprintf(stderr, "libsodium init failed\n");
        return 0;
    }

    FILE *f_in = fopen(in_file, "rb");
    if (f_in == NULL)
    {
        fprintf(stderr, "Error opening input file: %s\n", in_file);
        return 0;
    }

    // init libsodium hashing
    crypto_hash_sha256_state hash_state;
    crypto_hash_sha256_init(&hash_state);

    // read the file and update the hash
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f_in)) > 0)
    {
        crypto_hash_sha256_update(&hash_state, buffer, bytes_read);
    }

    // final hash
    crypto_hash_sha256_final(&hash_state, hash_output);

    fclose(f_in);
    return 1;
}

int sign(char *input, char *sign_out, char *keyf)
{
    // load keys[0]=n, keys[1]=d
    mpz_t keys[2];
    keyFile((char *)keyf, keys);

    // SHA-256
    unsigned char h[32];
    if (!compute_sha256(input, h))
    {
        fprintf(stderr, "sign: SHA-256 failed\n");
        mpz_clears(keys[0], keys[1], NULL);
        return 0;
    }

    mpz_t m, s;
    mpz_inits(m, s, NULL);
    mpz_import(m, sizeof(h), 1, 1, 0, 0, h);

    // s = m^d modn
    mpz_powm(s, m, keys[1], keys[0]);

    FILE *out = fopen(sign_out, "w");
    if (!out)
    {
        perror("sign: fopen sign_out");
        mpz_clears(m, s, keys[0], keys[1], NULL);
        return 0;
    }
    gmp_fprintf(out, "%Zd\n", s);
    fclose(out);

    mpz_clears(m, s, keys[0], keys[1], NULL);
    return 1;
}

int verify(char *input, char *sign_in, char *keyf)
{
    // load keys[0]=n and keys[1]=e
    mpz_t keys[2];
    keyFile((char *)keyf, keys);

    // SHA-256
    unsigned char h[32];
    if (!compute_sha256(input, h))
    {
        fprintf(stderr, "verify --> SHA-256 failed\n");
        mpz_clears(keys[0], keys[1], NULL);
        return 0;
    }

    FILE *sf = fopen(sign_in, "r");
    if (!sf)
    {
        perror("verify: fopen sign_in");
        mpz_clears(keys[0], keys[1], NULL);
        return 0;
    }
    mpz_t s;
    mpz_init(s);
    if (mpz_inp_str(s, sf, 10) == 0)
    {
        fprintf(stderr, "verify: bad signature format\n");
        fclose(sf);
        mpz_clears(s, keys[0], keys[1], NULL);
        return 0;
    }
    fclose(sf);

    // v = s^e modn
    mpz_t v, m;
    mpz_inits(v, m, NULL);
    mpz_powm(v, s, keys[1], keys[0]);

    mpz_import(m, sizeof(h), 1, 1, 0, 0, h);

    // validation check
    int ok = (mpz_cmp(v, m) == 0);
    printf("Signature is %s\n", ok ? "VALID" : "INVALID");

    mpz_clears(v, m, s, keys[0], keys[1], NULL);
    return ok ? 1 : 0;
}

// -a flag
void performance(char *input, char *cipherTxt, char *decipherTxt)
{
    FILE *fp = fopen("performance.txt", "w");
    if (fp == NULL)
        return;

    const char *sigTmp = "perf_sig.tmp";
    clock_t start, end;
    mpz_t keyLength;
    mpz_init(keyLength);
    mpz_t keys[2];

    // ---------1024------------
    printf("Running 1024-bit performance...\n");
    mpz_set_ui(keyLength, 1024);

    start = clock();
    generateRSAKeyPair(keyLength);
    end = clock() - start;
    long mem_keygen = get_peak_memory_kb();
    fprintf(fp, "1024 bit key length generation: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (KeyGen): %ld KB\n", mem_keygen);

    char pub1024[64] = "public_1024.key";
    char priv1024[64] = "private_1024.key";

    keyFile(pub1024, keys);
    start = clock();
    encryptDataRSA(input, cipherTxt, keys);
    end = clock() - start;
    long mem_enc = get_peak_memory_kb();
    fprintf(fp, "1024 bit encryption: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (Encryption): %ld KB\n", mem_enc);
    mpz_clears(keys[0], keys[1], NULL);

    keyFile(priv1024, keys);
    start = clock();
    decryptDataRSA(cipherTxt, decipherTxt, keys);
    end = clock() - start;
    long mem_dec = get_peak_memory_kb();
    fprintf(fp, "1024 bit decryption: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (Decryption): %ld KB\n", mem_dec);
    mpz_clears(keys[0], keys[1], NULL);

    start = clock();
    int s_ok = sign(input, sigTmp, priv1024);
    end = clock() - start;
    long mem_sign = get_peak_memory_kb();
    fprintf(fp, "1024 bit signing: %f seconds [%s]\n",
            (double)end / CLOCKS_PER_SEC, s_ok ? "OK" : "FAILED");
    fprintf(fp, "Peak Memory Usage (Signing): %ld KB\n", mem_sign);

    start = clock();
    int v_ok = verify(input, sigTmp, pub1024);
    end = clock() - start;
    long mem_ver = get_peak_memory_kb();
    fprintf(fp, "1024 bit verification: %f seconds [%s]\n",
            (double)end / CLOCKS_PER_SEC, v_ok ? "VALID" : "INVALID");
    fprintf(fp, "Peak Memory Usage (Verification): %ld KB\n\n", mem_ver);
    remove(sigTmp);

    // ---------2048------------
    printf("Running 2048-bit performance...\n");
    mpz_set_ui(keyLength, 2048);

    start = clock();
    generateRSAKeyPair(keyLength);
    end = clock() - start;
    mem_keygen = get_peak_memory_kb();
    fprintf(fp, "2048 bit key length generation: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (KeyGen): %ld KB\n", mem_keygen);

    char pub2048[64] = "public_2048.key";
    char priv2048[64] = "private_2048.key";

    keyFile(pub2048, keys);
    start = clock();
    encryptDataRSA(input, cipherTxt, keys);
    end = clock() - start;
    mem_enc = get_peak_memory_kb();
    fprintf(fp, "2048 bit encryption: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (Encryption): %ld KB\n", mem_enc);
    mpz_clears(keys[0], keys[1], NULL);

    keyFile(priv2048, keys);
    start = clock();
    decryptDataRSA(cipherTxt, decipherTxt, keys);
    end = clock() - start;
    mem_dec = get_peak_memory_kb();
    fprintf(fp, "2048 bit decryption: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (Decryption): %ld KB\n", mem_dec);
    mpz_clears(keys[0], keys[1], NULL);

    start = clock();
    s_ok = sign(input, sigTmp, priv2048);
    end = clock() - start;
    mem_sign = get_peak_memory_kb();
    fprintf(fp, "2048 bit signing: %f seconds [%s]\n",
            (double)end / CLOCKS_PER_SEC, s_ok ? "OK" : "FAILED");
    fprintf(fp, "Peak Memory Usage (Signing): %ld KB\n", mem_sign);

    start = clock();
    v_ok = verify(input, sigTmp, pub2048);
    end = clock() - start;
    mem_ver = get_peak_memory_kb();
    fprintf(fp, "2048 bit verification: %f seconds [%s]\n",
            (double)end / CLOCKS_PER_SEC, v_ok ? "VALID" : "INVALID");
    fprintf(fp, "Peak Memory Usage (Verification): %ld KB\n\n", mem_ver);
    remove(sigTmp);

    // ---------4096------------
    printf("Running 4096-bit performance...\n");
    mpz_set_ui(keyLength, 4096);

    start = clock();
    generateRSAKeyPair(keyLength);
    end = clock() - start;
    mem_keygen = get_peak_memory_kb();
    fprintf(fp, "4096 bit key length generation: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (KeyGen): %ld KB\n", mem_keygen);

    char pub4096[64] = "public_4096.key";
    char priv4096[64] = "private_4096.key";

    keyFile(pub4096, keys);
    start = clock();
    encryptDataRSA(input, cipherTxt, keys);
    end = clock() - start;
    mem_enc = get_peak_memory_kb();
    fprintf(fp, "4096 bit encryption: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (Encryption): %ld KB\n", mem_enc);
    mpz_clears(keys[0], keys[1], NULL);

    keyFile(priv4096, keys);
    start = clock();
    decryptDataRSA(cipherTxt, decipherTxt, keys);
    end = clock() - start;
    mem_dec = get_peak_memory_kb();
    fprintf(fp, "4096 bit decryption: %f seconds\n", (double)end / CLOCKS_PER_SEC);
    fprintf(fp, "Peak Memory Usage (Decryption): %ld KB\n", mem_dec);
    mpz_clears(keys[0], keys[1], NULL);

    start = clock();
    s_ok = sign(input, sigTmp, priv4096);
    end = clock() - start;
    mem_sign = get_peak_memory_kb();
    fprintf(fp, "4096 bit signing: %f seconds [%s]\n",
            (double)end / CLOCKS_PER_SEC, s_ok ? "OK" : "FAILED");
    fprintf(fp, "Peak Memory Usage (Signing): %ld KB\n", mem_sign);

    start = clock();
    v_ok = verify(input, sigTmp, pub4096);
    end = clock() - start;
    mem_ver = get_peak_memory_kb();
    fprintf(fp, "4096 bit verification: %f seconds [%s]\n",
            (double)end / CLOCKS_PER_SEC, v_ok ? "VALID" : "INVALID");
    fprintf(fp, "Peak Memory Usage (Verification): %ld KB\n\n", mem_ver);
    remove(sigTmp);

    mpz_clear(keyLength);
    fclose(fp);
    printf("Performance report saved to performance.txt\n");
}

void print_help()
{
    printf("Usage: ./rsa_assign_2 [options]\n\n");
    printf("  -g length   Perform RSA key-pair generation (e.g., 1024, 2048, 4096)\n");
    printf("  -e          Encrypt input and store results to output\n");
    printf("  -d          Decrypt input and store results to output\n");
    printf("  -s          Sign input file and store signature to output\n");
    printf("  -v path     Verify signature (path to signature file) against input file\n");
    printf("  -a          Performance analysis with three key lengths (1024, 2048, 4096)\n");
    printf("  -i path     Path to the input file\n");
    printf("  -o path     Path to the output file\n");
    printf("  -k path     Path to the key file\n\n");
    printf("  -h          This help message\n");
}

long get_peak_memory_kb()
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

int main(int argc, char *argv[])
{
    mpz_t keyLength;
    mpz_init(keyLength);
    char *inputFile, *outputFile, *keyFile, *func, *sigFile;
    mpz_set_si(keyLength, DEFAULTLEN);

    // handling flags from cli
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0)
        {
            print_help();
            continue;
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            if (argv[i + 1] != NULL)
            {
                inputFile = argv[i + 1];
                printf("Input file: %s\n", inputFile);
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            if (argv[i + 1] != NULL)
            {
                outputFile = argv[i + 1];
                printf("Output file: %s\n", outputFile);
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            if (argv[i + 1] != NULL)
            {
                keyFile = argv[i + 1];
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-g") == 0)
        {
            if (argv[i + 1] != NULL)
            {
                mpz_set_ui(keyLength, atoi(argv[i + 1]));
                generateRSAKeyPair(keyLength);
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-e") == 0)
        {
            if (outputFile != NULL && inputFile != NULL && keyFile != NULL)
            { // required -i -o -k (PUBLIC key)
                func = "encrypt";
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            if (outputFile != NULL && inputFile != NULL && keyFile != NULL)
            { // required -i -o -k (PRIVATE key)
                func = "decrypt";
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            if (outputFile != NULL && inputFile != NULL && keyFile != NULL)
            { // required -i -o -k (PRIVATE key)
                func = "sign";
                continue;
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            if (argv[i + 1] != NULL)
            {
                sigFile = argv[i + 1]; // signature path
                if (inputFile != NULL && keyFile != NULL)
                { // required -i -k (PUBLIC key) and -v <signature>
                    func = "verify";
                    continue;
                }
            }
            printf("Give arguments in right order\n");
        }
        else if (strcmp(argv[i], "-a") == 0)
        {
            func = "all";
            continue;
        }
    }

    // using fuctions based on the flags given in terminal
    if (func != NULL && strcmp(func, "encrypt") == 0)
    {
        printf("Encrypting ...\n");
        encrypt(inputFile, outputFile, keyFile); // public key n, e
    }
    if (func != NULL && strcmp(func, "decrypt") == 0)
    {
        printf("Decrypting ...\n");
        decrypt(inputFile, outputFile, keyFile); // private key n, d
    }
    if (func != NULL && strcmp(func, "sign") == 0)
    {
        printf("Signing ...\n");
        if (!sign(inputFile, outputFile, keyFile)) // private key n, d, Stores the signature in an output file -o
            fprintf(stderr, "Signing failed.\n");
        else
            printf("Signature written to %s\n", outputFile);
    }
    if (func != NULL && strcmp(func, "verify") == 0)
    {
        printf("Verifying ...\n");
        int ok = verify(inputFile, sigFile, keyFile); // public key n, e, Output whether the signature is VALID or INVALID
        printf("Verification result: %s\n", ok ? "VALID" : "INVALID");
    }
    if (func != NULL && strcmp(func, "all") == 0)
    {
        printf("Check file 'performance.txt' for statistics\n");
        performance("message.txt", "pCipher.txt", "pDecipher.txt");
    }

    mpz_clear(keyLength);
    return 0;
}
