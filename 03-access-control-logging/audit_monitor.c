#include "audit_monitor.h"

void usage(void)
{
	printf(
		"\n"
		"usage:\n"
		"\t./audit_monitor \n"
		"Options:\n"
		"-s, Prints malicious users\n"
		"-i <filename>, Prints table of users that modified "
		"the file <filename> and the number of modifications\n"
		"-h, Help message\n\n");

	exit(1);
}

int read_log_entry(FILE *log, Entry *e)
{
	static char filebuf[PATH_MAX];
	static char datebuf[11];
	static char timebuf[9];
	static char hashbuf[65];

	int uid, pid, op, denied;

	int n = fscanf(log,
				   "%d|%d|%1023[^|]|%10[^|]|%8[^|]|%d|%d|%64s\n",
				   &uid,
				   &pid,
				   filebuf,
				   datebuf,
				   timebuf,
				   &op,
				   &denied,
				   hashbuf);

	if (n != 8)
	{
		// eof wrong line
		return 0;
	}

	e->uid = uid;
	e->pid = (pid_t)pid;
	e->operation = op;
	e->action_denied = denied;

	e->filename = filebuf;
	e->date = datebuf;
	e->time = timebuf;
	e->filehash = hashbuf;

	return 1;
}

// ./audit_monitor -s
void list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	// start log from the beggining
	rewind(log);

	Entry entry;

	// array with denied =1
	struct
	{
		int uid;
		char filename[256];
	} uid_file_pairs[MAX_PAIRS];
	int pair_count = 0;

	// array uid and eachs num of denied files
	struct
	{
		int uid;
		int count;
	} user_counts[MAX_USERS];
	int user_count = 0;

	// init count
	for (int i = 0; i < MAX_USERS; i++)
	{
		user_counts[i].uid = -1;
		user_counts[i].count = 0;
	}

	while (read_log_entry(log, &entry))
	{

		if (entry.action_denied != 1)
			continue;

		if (entry.filename == NULL || entry.filename[0] == '\0')
			continue;

		// checkif uid exists in the arrays
		int exists = 0;
		for (int i = 0; i < pair_count; i++)
		{
			if (uid_file_pairs[i].uid == entry.uid &&
				strcmp(uid_file_pairs[i].filename, entry.filename) == 0)
			{
				exists = 1;
				break;
			}
		}

		if (exists)
			continue;

		// add new uid if there is space
		if (pair_count < MAX_PAIRS)
		{
			uid_file_pairs[pair_count].uid = entry.uid;
			strncpy(uid_file_pairs[pair_count].filename,
					entry.filename,
					sizeof(uid_file_pairs[pair_count].filename) - 1);
			uid_file_pairs[pair_count].filename[sizeof(uid_file_pairs[pair_count].filename) - 1] = '\0';
			pair_count++;
		}
		else
		{
			// fprintf(stderr, "Warning: MAX_PAIRS reached, ignoring extra entries\n");
		}

		// count++
		int found = 0;
		for (int j = 0; j < user_count; j++)
		{
			if (user_counts[j].uid == entry.uid)
			{
				user_counts[j].count++;
				found = 1;
				break;
			}
		}

		if (!found && user_count < MAX_USERS)
		{
			user_counts[user_count].uid = entry.uid;
			user_counts[user_count].count = 1;
			user_count++;
		}
	}

	// print results
	printf("Suspicious users (more than 5 distinct denied files):\n");
	int any = 0;
	for (int i = 0; i < user_count; i++)
	{
		if (user_counts[i].count > 5)
		{
			printf("  UID: %d (denied distinct files: %d)\n",
				   user_counts[i].uid,
				   user_counts[i].count);
			any = 1;
		}
	}

	if (!any)
	{
		printf("  None found.\n");
	}

	// return;
}

// ./audit_monitor -i <filename>
void list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	rewind(log);

	Entry entry;

	char target_path[PATH_MAX];
	char *rp = realpath(file_to_scan, target_path);
	const char *target = (rp != NULL) ? target_path : file_to_scan;

	int found_any = 0;

	// unique uids
	int users[MAX_USERS];
	int users_count = 0;

	// modifications per user
	struct
	{
		int uid;
		int mods;
	} user_mods[MAX_USERS];
	int user_mods_count = 0;

	// Unique hashes modifications
	char hashes[MAX_HASHES][65];
	int hash_count = 0;

	while (read_log_entry(log, &entry))
	{
		if (strcmp(entry.filename, target) != 0)
			continue;

		found_any = 1;

		// uid who accessed the file
		int seen = 0;
		for (int i = 0; i < users_count; i++)
		{
			if (users[i] == entry.uid)
			{
				seen = 1;
				break;
			}
		}
		if (!seen && users_count < MAX_USERS)
		{
			users[users_count++] = entry.uid;
		}

		// modification op=2
		if (entry.operation == 2 && entry.action_denied == 0)
		{
			int found = 0;
			for (int i = 0; i < user_mods_count; i++)
			{
				if (user_mods[i].uid == entry.uid)
				{
					user_mods[i].mods++;
					found = 1;
					break;
				}
			}
			if (!found && user_mods_count < MAX_USERS)
			{
				user_mods[user_mods_count].uid = entry.uid;
				user_mods[user_mods_count].mods = 1;
				user_mods_count++;
			}

			// distinct hashes
			int hash_exists = 0;
			for (int h = 0; h < hash_count; h++)
			{
				if (strcmp(hashes[h], entry.filehash) == 0)
				{
					hash_exists = 1;
					break;
				}
			}
			if (!hash_exists && hash_count < MAX_HASHES)
			{
				strncpy(hashes[hash_count], entry.filehash, 64);
				hashes[hash_count][64] = '\0';
				hash_count++;
			}
		}
	}

	if (!found_any)
	{
		printf("No log entries found for file: %s\n", target);
		return;
	}

	printf("File: %s\n", target);

	printf("\nUsers who accessed this file:\n");
	for (int i = 0; i < users_count; i++)
	{
		printf("  UID: %d\n", users[i]);
	}

	printf("\nModifications per user (successful writes):\n");
	if (user_mods_count == 0)
	{
		printf("  No successful modifications recorded.\n");
	}
	else
	{
		for (int i = 0; i < user_mods_count; i++)
		{
			printf("  UID: %d -> %d modifications\n",
				   user_mods[i].uid,
				   user_mods[i].mods);
		}
	}

	printf("\nUnique modifications (distinct hashes): %d\n", hash_count);
	// return;
}

int main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("/tmp/access_audit.log", "r");
	if (log == NULL)
	{
		printf("Error opening log file \"%s\"\n", "./access_audit.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:s")) != -1)
	{
		switch (ch)
		{
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}
	}

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	fclose(log);
	argc -= optind;
	argv += optind;

	return 0;
}
