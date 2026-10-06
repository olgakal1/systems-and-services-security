#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        abort();
    }

    return sd;
}

SSL_CTX *InitCTX(void)
{
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS client context (TLS_client_method)
     * 3. Load CA certificate to verify server
     * 4. Configure SSL_CTX to verify server certificate
     */

    const SSL_METHOD *method;
    SSL_CTX *ctx;
    // SSL_CTX *ctx = NULL;

    // Init OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // New TLS client context
    // method = TLS_client_method();
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load CA to verify server
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load CA file (ca.crt)\n");
        exit(EXIT_FAILURE);
    }

    // Verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    /* TODO:
     * 1. Load client certificate using SSL_CTX_use_certificate_file
     * 2. Load client private key using SSL_CTX_use_PrivateKey_file
     * 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     */

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

void ShowCerts(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl); // get the server's certificate
    if (cert != NULL)
    {
        char *line;
        printf("Server certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("  Subject: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("  Issuer : %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    }
    else
    {
        printf("Info: No server certificate presented.\n");
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    char buf[2048];
    char acClientRequest[1024] = {0};
    int bytes;

    /* TODO:
     * 1. Initialize SSL context using InitCTX
     * 2. Load client certificate and key using LoadCertificates
     */

    // 1) Initialize SSL context
    ctx = InitCTX();
    // 2) Load client certificate & key for mTLS
    LoadCertificates(ctx, "client.crt", "client.key");

    server = OpenConnection(hostname, port);
    ssl = SSL_new(ctx); // Create SSL object and attach socket
    if (!ssl)
    {
        ERR_print_errors_fp(stderr);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL_set_fd(ssl, server);

    /* TODO:
     * 1. Establish SSL connection using SSL_connect
     * 2. Ask user to enter username and password
     * 3. Build XML message dynamically
     * 4. Send XML message over SSL
     * char username[64], password[64];
        printf("Enter username: ");
        scanf("%63s", username);
        printf("Enter password: ");
        scanf("%63s", password);

        char msg[256];
        snprintf(msg, sizeof(msg),
                 "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
                 username, password);

        SSL_write(ssl, msg, strlen(msg));
     * 5. Read server response and print it
     */

    // TLS handshake
    if (SSL_connect(ssl) == FAIL)
    {
        ERR_print_errors_fp(stderr);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Connected with %s\n", SSL_get_cipher(ssl));
    ShowCerts(ssl); // proairetiko

    // enter usernm, password
    char acUsername[64] = {0};
    char acPassword[64] = {0};
    printf("Enter the User Name : ");
    if (scanf("%63s", acUsername) != 1)
    {
        fprintf(stderr, "Input error\n");
        goto done;
    }
    printf("Enter the Password : ");
    if (scanf("%63s", acPassword) != 1)
    {
        fprintf(stderr, "Input error\n");
        goto done;
    }

    //  XML
    const char *cpRequestMessage =
        "<Body><User>%s</UserName><Password>%s</Password></Body>";

    snprintf(acClientRequest, sizeof(acClientRequest), cpRequestMessage, acUsername, acPassword);

    if (SSL_write(ssl, acClientRequest, (int)strlen(acClientRequest)) <= 0)
    {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        goto done;
    }
    buf[bytes] = '\0';
    printf("Received: \"%s\"\n", buf);

done:
    if (ssl)
        SSL_free(ssl);
    if (server >= 0)
        close(server);
    if (ctx)
        SSL_CTX_free(ctx);
    return 0;

    /*SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;*/
}
