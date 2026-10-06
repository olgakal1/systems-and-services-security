#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

// rclient.c — rogue client uses a unknown/untrusted CA

static int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("Connection failed");
        close(sd);
        exit(EXIT_FAILURE);
    }
    return sd;
}

static SSL_CTX *InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // method = TLS_client_method();
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load rogue CA
    if (SSL_CTX_load_verify_locations(ctx, "rogue_ca.crt", NULL) != 1)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load rogue CA (rogue_ca.crt)\n");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

static void LoadCertificates(SSL_CTX *ctx, const char *CertFile, const char *KeyFile)
{
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Cannot load client certificate: %s\n", CertFile);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Cannot load client private key: %s\n", KeyFile);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the client certificate\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        return 0;
    }

    const char *hostname = argv[1];
    int port = atoi(argv[2]);

    SSL_CTX *ctx = InitCTX();
    LoadCertificates(ctx, "rogue_client.crt", "rogue_client.key");

    int server = OpenConnection(hostname, port);

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        ERR_print_errors_fp(stderr);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL_set_fd(ssl, server);

    // failure in handshake
    if (SSL_connect(ssl) != 1)
    {
        fprintf(stderr, "[rclient] SSL_connect failed (expected for rogue client)\n");
        ERR_print_errors_fp(stderr);
        // καθάρισμα
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    // sos
    printf("[rclient] Unexpected: handshake succeeded. Check your server CA setup.\n");

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
