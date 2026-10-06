***ASSIGNMENT 2 --> Elliptic Curve Diffie–Hellman (ECDH) Key Exchange with Key Derivation and RSA (Rivest–Shamir–Adleman) with Digital Signatures***


# Elliptic Curve Diffie-Hellman (ECDH) Key Exchange with Key Derivation 

*OVERVIEW* :

    This project implements an Elliptic Curve Diffie-Hellman (ECDH) key exchange using the **libsodium's Curve 25519 Curve, GMP library**. The program generates public and private keys for two parties, Alice and Bob (A=a*G, B=b*G). It computes shared secrets based on their private keys and the other party's public key (S_A=a*B, S_B=b*A). Finally, it applies a KDF *crypto_kdf_derive_from_key* for the encryption and MAC, to derive two seperate keys. The results, including the public keys and shared secrets, are printed in hexadecimal format to a specified output file.

*Command Line Options for ECDH Tool* :

    -o path      Path to output file 
    -a number    Alice's private key (optional, hexadecimal format) 
    -b number    Bob's private key (optional, hexadecimal format) 
    -c context   Context string for key derivation (default: "ECDH_KDF") 
    -h           This help message

*COMPILATION AND EXECUTION* :

    Compile the ecdh_assign_2 : gcc -Wall -g ecdh_assign_2.c -lsodium -o ecdh_assign_2

    Or you may use the default Makefile given. 

    In order to test the program you can run the following examples:

        1. Random keys: ./ecdh_assign_2 -o output.txt 
        2. With fixed keys: ./ecdh_assign_2 -o output.txt -a 0x1a2b3c -b 0x1a2cb7 
        3. With custom context for KDF:  ./ecdh_assign_2 -o output.txt -a 0x1a2b3c -b 0x1a2cb7 -c "koukou25"
    
    The *ecdh.txt* file contains all the results after running the program


## RSA Algorithm with Digital Signatures

*OVERVIEW* :

    This project implements the RSA key-pair generation algorithm, encryption and decryption functions, and digital signature creation and verification using the **libsodium's SHA-256 hashing, GMP library**. The program generates RSA key pairs consisting of a public key --> [n,e] and a private key --> [n,d], where  n = p * q, a prime e where (e % lambda(n) != 0) AND (gcd(e, lambda) == 1) and d where d is the modular inverse of (e, lambda). The program generates three sets of key pairs (1024, 2048, 4096 bits) and measures the generation, encryption, decryption, signing and verification time, as well as the peak memory usage for each operation.

*RSA PROJECT STRUCTURE* :

    The project consists of 3 main files .c :

        1. "keygen.c" --> Handles key generation for the RSA algorithm, creating both private keys [n,d] and public keys [n,e].
        2. "endec.c" --> Contains functions for encrypting and decrypting messages.
        3. "rsa_assign_2.c" --> Contains the main function that processes command-line flags and implements the algorithm.

*Command Line Options for RSA Tool* :
    
        -i path        Path to the input file 
        -o path        Path to the output file
        -k path        Path to the key file 
        -g length      Perform RSA key-pair generation given a key length "length" 
        -d             Decrypt input and store results to output
        -e             Encrypt input and store results to output
        -s             Sign input file and store signature to output
        -v path        Verify signature (path to signature file) against input file
        -a             Performance analysis with three key lengths (1024, 2048, 4096)
        -h             This help message

*COMPILATION AND EXECUTION* :

    Compile the rsa_assign_2 : gcc -Wall -g rsa_assign_2.c endec.c keygen.c -lgmp -lsodium -o rsa_assign_2

    Or you may use the default Makefile given. 

    In order to test the program you can run the following examples:

            1. Key Generation: ./rsa_assign_2 -g 2048  --> Generates public_2048.key and private_2048.key.
            2. Encryption: ./rsa_assign_2 -i plaintext.txt -o ciphertext.txt -k public_2048.key -e
            3. Decryption: ./rsa_assign_2 -i ciphertext.txt -o decrypted.txt -k private_2048.key -d 
            4. Signing  : ./rsa_assign_2 -i input.txt -o signature_output -k private_2048.key -s
            5. Verification  : ./rsa_assign_2 -i input.txt -k public_2048.key -v signature_output --> Output: Signature is VALID or Signature is INVALID 
            6. Performance Analysis: ./rsa_assign_2 -a performance.txt

    The *performance.txt* file contains all the results after running the program