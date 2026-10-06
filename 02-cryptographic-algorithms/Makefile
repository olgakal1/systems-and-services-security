CC=gcc
CFLAGS= -Wall -g
LIBS1= -lsodium
LIBS2= -lgmp -lsodium

SOURCES1 = ecdh_assign_2.c 
SOURCES2 = keygen.c endec.c rsa_assign_2.c 

OBJS1 = $(SOURCES1:.c=.o)
OBJS2 = $(SOURCES2:.c=.o)

all: ecdh_assign_2 rsa_assign_2

ecdh_assign_2: ecdh_assign_2.c
	$(CC) $(CFLAGS) -o ecdh_assign_2 ecdh_assign_2.c $(LIBS1)

rsa_assign_2: rsa_assign_2.c
	$(CC) $(CFLAGS) -o rsa_assign_2 rsa_assign_2.c $(LIBS2)

clean:
	rm -f ecdh_assign_2 rsa_assign_2 private* public* performance.txt pCipher.txt pDecipher.txt $(OBJS1) $(OBJS2)
