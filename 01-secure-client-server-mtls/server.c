#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY; // htons(INADDR_ANY)

    if (sd < 0)
    {
        perror("socket creation");
        abort();
    }

    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0)
    {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

SSL_CTX *InitServerCTX(void)
{
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS server context (TLS_server_method)
     * 3. Load CA certificate for client verification
     * 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method;

    // Init OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // method = TLS_server_method();
    method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // mTLS load CA and cert
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1)
    {
        fprintf(stderr, "Failed to load CA file (ca.crt)\n");
        ERR_print_errors_fp(stderr);
        abort();
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
     * 2. Load server private key using SSL_CTX_use_PrivateKey_file
     * 3. Check that private key matches the certificate using SSL_CTX_check_private_key
     */

    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load server certificate '%s'\n", CertFile);
        abort();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load server key '%s'\n", KeyFile);
        abort();
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL *ssl)
{
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
     * 2. Print Subject and Issuer names
     */

    // print client certificate
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); // Get certificates if available

    if (cert != NULL)
    {
        printf("== Server certificate ==\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        OPENSSL_free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer:  %s\n", line);
        OPENSSL_free(line);

        X509_free(cert);
    }
    else
    {
        printf("No certificate presented.\n");
    }

    // verify certificate mTLS
    long verify = SSL_get_verify_result(ssl);
    if (verify == X509_V_OK)
        printf("Certificate verification: OK\n");
    else
        printf("Certificate verification failed (code: %ld)\n", verify);
}

// help functon for servlet
int checkClientRequest(const char *xml)
{

    if (!xml)
        return 0;

    const char *userStart = strstr(xml, "<User>");
    const char *userEnd = strstr(xml, "</UserName>");
    if (!userStart)
    {
        userStart = strstr(xml, "<UserName>");
    }

    const char *passStart = strstr(xml, "<Password>");
    const char *passEnd = strstr(xml, "</Password>");

    if (!userStart || !userEnd || !passStart || !passEnd)
        return 0;

    if (strstr(xml, "<UserName>"))
        userStart += strlen("<UserName>");
    else
        userStart += strlen("<User>");
    passStart += strlen("<Password>");

    // buff for user (Sousi), pass (123)
    char user[64] = {0};
    char pass[64] = {0};

    strncpy(user, userStart, userEnd - userStart);
    user[userEnd - userStart] = '\0';

    strncpy(pass, passStart, passEnd - passStart);
    pass[passEnd - passStart] = '\0';

    // check credentials for login
    if (strcmp(user, "Sousi") == 0 && strcmp(pass, "123") == 0)
        return 1;
    return 0;
}

void Servlet(SSL *ssl)
{
    char buf[1024] = {0};
    int sd;

    if (SSL_accept(ssl) == FAIL)
    {
        printf("peer did not return a certificate or returned an invalid one\n");
        ERR_print_errors_fp(stderr);
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
        return;
    }

    ShowCerts(ssl);

    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0)
    {
        ERR_print_errors_fp(stderr);
        sd = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sd);
        return;
    }

    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract username and password
     * 2. Compare credentials to predefined values (e.g., "sousi"/"123")
     * 3. Send appropriate XML response back to client
     */

    const char *serverResponse =
        "<Body>"
        "<Name>sousi.com</Name>"
        "<year>1.5</year>"
        "<BlogType>Embedede and c c++</BlogType>"
        "<Author>John Johny</Author>"
        "</Body>";

    if (checkClientRequest(buf))
    {
        SSL_write(ssl, serverResponse, strlen(serverResponse));
    }
    else
    {
        printf("Invalid client request:\n%s\n", buf);
        const char *invalidMsg = "Invalid Message";
        SSL_write(ssl, invalidMsg, strlen(invalidMsg));
    }

    sd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */
    ctx = InitServerCTX();
    LoadCertificates(ctx, "server.crt", "server.key");

    int server = OpenListener(port);
    printf("Server listening on port %d\n", port);

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len);
        if (client < 0)
        {
            perror("can't connect a client");
            continue;
        }
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */

        ssl = SSL_new(ctx);
        if (!ssl)
        {
            ERR_print_errors_fp(stderr);
            close(client);
            continue;
        }

        SSL_set_fd(ssl, client);
        Servlet(ssl);
    }

    close(server);
    SSL_CTX_free(ctx);
}
