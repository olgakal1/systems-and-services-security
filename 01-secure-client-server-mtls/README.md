***ASSIGNMENT 1 --> Secure Server-Client Program using OpenSSL in C (with Mutual TLS)***


*OVERVIEW* :

    This project implements a secure connection between client and server using the **TLS1.2** protocol and the **OpenSSL** library in C, whilst both client and server authenticate each other using **X.509 certificates (mutual TLS)**.


*PROJECT STRUCTURE* :

    The project consists of 3 main files .c :
        1. "server.c" --> TLS server skeleton. Implements the secure TLS server using OpenSSL. Requires client certificate (mutual authentication). Validates the request and responds with either a valid XML response or an “Invalid Message” reply.
        2. "client.c" --> TLS client skeleton. Legitimate client that connects securely using the signed CA certificate. Sends an XML login request (username + password) to the server
        3. "rclient.c" --> rogue client signed by unknown/untrusted CA


*CERTIFICATE GUIDE* :

    # Create a Certificate Authority (CA) and use it to sign both server and client certificates.

        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=RootCA"
    
    # Generate Server Certificate (signed by CA)

        --Create Server key and CSR
        openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=localhost"

        --Sign with CA
        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

    # Generate Client Certificate (signed by CA) 

        --Create client key and CSR
        openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=client"

        --Sign with CA
        openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

    # Generate Client Certificate (signed by another CA) --> Rogue CA and Rogue Client

        --Create rogue CA
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout rogue_ca.key -out rogue_ca.crt -subj "/C=GR/ST=Crete/L=Chania/O=RogueCA/OU=Lab/CN=RogueRootCA"

        --Create rogue client key and CSR
        openssl req -new -newkey rsa:2048 -nodes -keyout rogue_client.key -out rogue_client.csr -subj "/C=GR/ST=Crete/L=Chania/O=RogueClient/OU=Lab/CN=rogue-client"

        --Sign with rogue CA
        openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial -out rogue_client.crt -days 365 -sha256


*COMPILATION AND EXECUTION* :

    Compile the Server: gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto 
    Compile the Client : gcc -Wall -o client  client.c -L/usr/lib -lssl -lcrypto 
    Compile the Rogue Client : gcc -Wall -o rclient  rclient.c -L/usr/lib -lssl -lcrypto 

    Or you may use the default Makefile given. 

    1. First run the server. Example: ./server  8082  

        The expected output is : Server listening on port 8082

        a. What is the number 8082? 
            The number 8082 is the TCP port the server listens on

        b. Can you run it on number 80, 443, 124? How can you achieve it? 
            On first try no, when you run ./server 80 or 443 or 124 the expected output is: Can't bind port: Permission denied. Aborted ( core dumped )
            However you can achieve this by using the sudo command  (e.g. sudo ./server 80)

    2. Then run the client. Example: ./client  127.0.0.1 8082  

        The expected output is: Enter the User Name : Sousi
                                Enter the Password : 123

        a. What is 127.0.0.1? 
            The number 127.0.0.1 is the localhost IP

        b. What is 8082?
            The number 8082 is the TCP port the server listens on
    
    3. If the client sends a valid request then server gives a proper response like the one below:

        The expected output is :    Enter the User Name : Sousi
                                    Enter the Password : 123
                                    Client message: <Body><User>Sousi</UserName><Password>123</Password></Body>
                                    Received: "<Body><Name>sousi.com</Name><year>1.5</year><BlogType>Embedede and c c++</BlogType><Author>John Johny</Author></Body>"
    

    4. If the client sends a invalid request to the server, then the server responds to an 
    “Invalid message”.

        The expected output is: Enter the User Name : Sousi
                                Enter the Password : 12345
                                Client message: <Body><User>Sousi</UserName><Password>12345</Password></Body>
                                Invalid client request: <Body><User>Sousi</UserName><Password>12345</Password></Body>
                                Received: "Invalid Message"

    5. Lastly run the rogue client. Example: ./rclient 127.0.0.1 8082

        The expected output is: [rclient] SSL_connect failed (expected for rogue client)
                                peer did not return a certificate or returned an invalid one


*FILES AND COMMANDS* :

    1. server.c :   - OpenListener
                    - Initializes OpenSSL (InitServerCTX)
                    - Loads CA, server certificate and private key (LoadCertificates)
                    - Verifies client certificate
                    - Check client credentials and validate them (CheckClientRequest)

    2. client.c :   - OpenConnection
                    - Initializes OpenSSL (InitCTX)
                    - Loads CA, client certificate and private key (LoadCertificates)
                    - Enters credentials (username + password)

    3. rclient.c :  - Same as client.c
                    - Loads a rogue CA and an invalid certificate
                    - Attempts to connect to server and fails during handshake
                    