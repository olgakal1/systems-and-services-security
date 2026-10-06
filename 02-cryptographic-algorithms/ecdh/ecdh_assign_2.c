#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

// help message
static void print_help(const char *prog)
{
    printf("Usage: %s -o path [-a hex] [-b hex] [-c context] [-h]\n"
           "-o path      Path to output file\n"
           "-a number    Alice's private key (optional, hexadecimal format)\n"
           "-b number    Bob's private key (optional, hexadecimal format)\n"
           "-c context   8-byte context for KDF (default: \"ECDH_KDF\")\n"
           "-h           This help message\n",
           prog);
}

// converts a hex to 32 bytes
// if the input has fewer than 64 bytes we use left padding with 0000...
static int hex_to_32bytes(const char *hex, unsigned char out[32])
{
    const char *p = hex;
    if (strlen(p) >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    size_t inlen = strlen(p);
    if (inlen > 64)
        return -1;

    // 64-char buffer with left zero padding
    char buf[65];
    memset(buf, '0', 64);
    buf[64] = '\0';
    memcpy(buf + (64 - inlen), p, inlen);

    size_t binlen = 0;
    if (sodium_hex2bin(out, 32, buf, 64, NULL, &binlen, NULL) != 0)
        return -1;
    return binlen == 32 ? 0 : -1;
}

// binary --> hex
static void bytes_to_hex(const unsigned char *in, size_t len, char *hex_out, size_t hex_out_sz)
{
    // len*2 + 1 bytes needed
    sodium_bin2hex(hex_out, hex_out_sz, in, len);
}

int main(int argc, char **argv)
{
    // init libsodium
    if (sodium_init() < 0)
    {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    const char *out_path = NULL;
    const char *a_hex = NULL;
    const char *b_hex = NULL;
    char context[9] = "ECDH_KDF"; // 8 bytes for crypto_kdf

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-h"))
        {
            print_help(argv[0]);
            return 0;
        }
        else if (!strcmp(argv[i], "-o") && i + 1 < argc)
        {
            out_path = argv[++i];
        }
        else if (!strcmp(argv[i], "-a") && i + 1 < argc)
        {
            a_hex = argv[++i];
        }
        else if (!strcmp(argv[i], "-b") && i + 1 < argc)
        {
            b_hex = argv[++i];
        }
        else if (!strcmp(argv[i], "-c") && i + 1 < argc)
        {
            size_t L = strlen(argv[i + 1]);
            if (L != 8)
            {
                fprintf(stderr, "Context must be 8 chars\n");
                return 2;
            }
            memcpy(context, argv[++i], 8);
            context[8] = '\0';
        }
        else
        {
            fprintf(stderr, "Unknown/invalid args. Use -h.\n");
            return 2;
        }
    }
    if (!out_path)
    {
        print_help(argv[0]);
        return 2;
    }

    // private and public key buffers 32 bytes
    unsigned char a_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char b_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char a_pk[crypto_scalarmult_BYTES];
    unsigned char b_pk[crypto_scalarmult_BYTES];

    // generate alice's secret
    if (a_hex)
    {
        if (hex_to_32bytes(a_hex, a_sk) != 0)
        {
            fprintf(stderr, "Bad -a hex\n");
            return 3;
        }
    }
    else
    {
        randombytes_buf(a_sk, sizeof a_sk);
    }

    // generate bob's secret
    if (b_hex)
    {
        if (hex_to_32bytes(b_hex, b_sk) != 0)
        {
            fprintf(stderr, "Bad -b hex\n");
            return 3;
        }
    }
    else
    {
        randombytes_buf(b_sk, sizeof b_sk);
    }

    // Public keys
    // A=a*G    B=b*G
    if (crypto_scalarmult_base(a_pk, a_sk) != 0 ||
        crypto_scalarmult_base(b_pk, b_sk) != 0)
    {
        fprintf(stderr, "Public key generation failed\n");
        return 4;
    }

    // Shared secrets
    // S_A=a*B    S_B=b*A
    unsigned char shared_a[crypto_scalarmult_BYTES];
    unsigned char shared_b[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_a, a_sk, b_pk) != 0 ||
        crypto_scalarmult(shared_b, b_sk, a_pk) != 0)
    {
        fprintf(stderr, "Shared secret computation failed\n");
        return 5;
    }

    // secret match confirmation
    int secrets_match = sodium_memcmp(shared_a, shared_b, sizeof shared_a) == 0;

    // derives 2 32-byte keys from shared secret with KDF
    // we'll use subkey 1 for the Encryption key
    // we'll use subkey 2 for the MAC key
    unsigned char enc_a[32], mac_a[32];
    unsigned char enc_b[32], mac_b[32];

    if (crypto_kdf_derive_from_key(enc_a, sizeof enc_a, 1, context, shared_a) != 0 ||
        crypto_kdf_derive_from_key(mac_a, sizeof mac_a, 2, context, shared_a) != 0 ||
        crypto_kdf_derive_from_key(enc_b, sizeof enc_b, 1, context, shared_b) != 0 ||
        crypto_kdf_derive_from_key(mac_b, sizeof mac_b, 2, context, shared_b) != 0)
    {
        fprintf(stderr, "KDF failed\n");
        return 6;
    }

    // convert to hex
    char a_pk_hex[crypto_scalarmult_BYTES * 2 + 1];
    char b_pk_hex[crypto_scalarmult_BYTES * 2 + 1];
    char sA_hex[crypto_scalarmult_BYTES * 2 + 1];
    char sB_hex[crypto_scalarmult_BYTES * 2 + 1];
    char encA_hex[64 * 2 + 1], encB_hex[64 * 2 + 1];
    char macA_hex[64 * 2 + 1], macB_hex[64 * 2 + 1];
    bytes_to_hex(a_pk, sizeof a_pk, a_pk_hex, sizeof a_pk_hex);
    bytes_to_hex(b_pk, sizeof b_pk, b_pk_hex, sizeof b_pk_hex);
    bytes_to_hex(shared_a, sizeof shared_a, sA_hex, sizeof sA_hex);
    bytes_to_hex(shared_b, sizeof shared_b, sB_hex, sizeof sB_hex);
    bytes_to_hex(enc_a, sizeof enc_a, encA_hex, sizeof encA_hex);
    bytes_to_hex(enc_b, sizeof enc_b, encB_hex, sizeof encB_hex);
    bytes_to_hex(mac_a, sizeof mac_a, macA_hex, sizeof macA_hex);
    bytes_to_hex(mac_b, sizeof mac_b, macB_hex, sizeof macB_hex);

    // Write output report file
    FILE *fp = fopen(out_path, "w");
    if (!fp)
    {
        perror("fopen");
        return 7;
    }

    fprintf(fp, "Alice's Public Key:\n%s\n\n", a_pk_hex);
    fprintf(fp, "Bob's Public Key:\n%s\n\n", b_pk_hex);
    fprintf(fp, "Shared Secret (Alice):\n%s\n\n", sA_hex);
    fprintf(fp, "Shared Secret (Bob):\n%s\n\n", sB_hex);
    fprintf(fp, "Shared secrets %s!\n\n", secrets_match ? "match" : "DO NOT MATCH");

    fprintf(fp, "Derived Encryption Key (Alice):\n%s\n\n", encA_hex);
    fprintf(fp, "Derived Encryption Key (Bob):\n%s\n\n", encB_hex);

    // verify whether the keys match or not
    fprintf(fp, "Encryption keys %s!\n\n",
            sodium_memcmp(enc_a, enc_b, sizeof enc_a) == 0 ? "match" : "DO NOT MATCH");

    fprintf(fp, "Derived MAC Key (Alice):\n%s\n\n", macA_hex);
    fprintf(fp, "Derived MAC Key (Bob):\n%s\n\n", macB_hex);

    // verify whether the keys match or not
    fprintf(fp, "MAC keys %s!\n", sodium_memcmp(mac_a, mac_b, sizeof mac_a) == 0 ? "match" : "DO NOT MATCH");

    fclose(fp);

    return 0;
}
