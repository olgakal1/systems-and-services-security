#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

typedef struct log_entry
{
    int uid;
    pid_t pid;

    int operation;     // create=0, open=1, write=2, close=3
    int action_denied; // allowed=0 denied=1

    char *date;
    char *time;

    char *filehash;
    char *filename;
} Entry;

#define MAX_USERS 1024
#define MAX_PAIRS 256
#define MAX_HASHES 2048

void usage(void);
int read_log_entry(FILE *log, Entry *e);
void list_unauthorized_accesses(FILE *log);
void list_file_modifications(FILE *log, char *file_to_scan);
