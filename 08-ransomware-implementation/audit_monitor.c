#include "audit_monitor.h"

// assignment 8 extras
#include <time.h>
#include <limits.h>

#define WINDOW_SECONDS (20 * 60) // 20 mins

// how long after open plaintext we consider a related .enc event
#define WORKFLOW_MAX_GAP_SECONDS (20 * 60)

static void detect_ransomware(FILE *log, int threshold_X);
static time_t parse_utc_ts(const char *date_yyyy_mm_dd, const char *time_hh_mm_ss);
static int ends_with(const char *s, const char *suffix);
static int starts_with(const char *s, const char *prefix);

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
		"-r <X>, Ransomware detection (burst create >=X within 20min + .enc workflow)\n"
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

	int did_anything = 0; // extra assign 8

	while ((ch = getopt(argc, argv, "hi:sr:")) != -1)
	{
		switch (ch)
		{
		case 'i':
		{
			list_file_modifications(log, optarg);
			did_anything = 1;
			break;
		}
		case 's':
		{
			list_unauthorized_accesses(log);
			did_anything = 1;
			break;
		}
		case 'r':
		{
			// extra assign 8
			int X = atoi(optarg);
			if (X <= 0)
				X = 50;
			detect_ransomware(log, X);
			did_anything = 1;
			break;
		}
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

	// extra assign 8
	if (!did_anything)
	{
		usage();
	}

	return 0;
}

// extra assign 8
// ransomware detection

typedef struct
{
	time_t ts;
	char path[PATH_MAX];
} CreateEvent;

typedef struct
{
	int pid;
	time_t ts;
	char plain_path[PATH_MAX];
} PlainOpenEvent;

static void detect_ransomware(FILE *log, int threshold_X)
{
	rewind(log);

	CreateEvent *creates = NULL;
	size_t c_len = 0, c_cap = 0;

	PlainOpenEvent *opens = NULL;
	size_t o_len = 0, o_cap = 0;

	Entry entry;

	printf("=== Ransomware Detection (threshold X=%d, window=20min) ===\n", threshold_X);

	while (read_log_entry(log, &entry))
	{
		if (!(starts_with(entry.filename, "/home/student/data/") ||
			  starts_with(entry.filename, "/home/student/target/")))
		{
			continue;
		}

		time_t ts = parse_utc_ts(entry.date, entry.time);
		if (ts == (time_t)-1)
			continue;

		// file creation op=0
		// if (entry.operation == 0 && entry.action_denied == 0)
		if ((entry.operation == 0 || entry.operation == 2) &&
			entry.action_denied == 0 &&
			ends_with(entry.filename, ".enc"))
		{
			if (c_len == c_cap)
			{
				c_cap = (c_cap == 0) ? 128 : c_cap * 2;
				creates = realloc(creates, c_cap * sizeof(CreateEvent));
				if (!creates)
				{
					perror("realloc");
					exit(1);
				}
			}
			creates[c_len].ts = ts;
			strncpy(creates[c_len].path, entry.filename, PATH_MAX - 1);
			creates[c_len].path[PATH_MAX - 1] = '\0';
			c_len++;

			// drop entries if >20min
			size_t start = 0;
			while (start < c_len && (ts - creates[start].ts) > WINDOW_SECONDS)
				start++;

			if (start > 0)
			{
				memmove(creates, creates + start, (c_len - start) * sizeof(CreateEvent));
				c_len -= start;
			}

			if ((int)c_len >= threshold_X)
			{
				printf("[ALERT] High-volume file creation: %zu create-events within last 20 minutes (threshold=%d)\n",
					   c_len, threshold_X);
				printf("        Latest created: %s\n", entry.filename);
			}
		}

		// remember plaintext opens
		//  if (entry.operation == 1 && entry.action_denied == 0 && !ends_with(entry.filename, ".enc"))
		if ((entry.operation == 1 || entry.operation == 2) &&
			entry.action_denied == 0 &&
			!ends_with(entry.filename, ".enc"))

		{
			if (o_len == o_cap)
			{
				o_cap = (o_cap == 0) ? 128 : o_cap * 2;
				opens = realloc(opens, o_cap * sizeof(PlainOpenEvent));
				if (!opens)
				{
					perror("realloc");
					exit(1);
				}
			}
			opens[o_len].pid = (int)entry.pid;
			opens[o_len].ts = ts;
			strncpy(opens[o_len].plain_path, entry.filename, PATH_MAX - 1);
			opens[o_len].plain_path[PATH_MAX - 1] = '\0';
			o_len++;
		}

		// flag .enc activity that follows plaintext open  same pid
		if ((entry.operation == 0 || entry.operation == 2) &&
			entry.action_denied == 0 &&
			ends_with(entry.filename, ".enc"))
		{
			size_t L = strlen(entry.filename);
			if (L <= 4)
				continue; // safety checks

			// plaintext candidate --> remove the .enc
			char plain_candidate[PATH_MAX];
			strncpy(plain_candidate, entry.filename, PATH_MAX - 1);
			plain_candidate[PATH_MAX - 1] = '\0';
			plain_candidate[L - 4] = '\0';

			// search backwards for same pid, within time window
			for (ssize_t i = (ssize_t)o_len - 1; i >= 0; i--)
			{
				if (opens[i].pid != (int)entry.pid)
					continue;

				if ((ts - opens[i].ts) > WORKFLOW_MAX_GAP_SECONDS)
					break; // older opens for this pid

				if (strcmp(opens[i].plain_path, plain_candidate) == 0)
				{
					printf("[ALERT] Encryption workflow: PID=%d opened '%s' then produced '%s' (op=%d)\n",
						   (int)entry.pid, opens[i].plain_path, entry.filename, entry.operation);
					break;
				}
			}
		}
	}

	free(creates);
	free(opens);

	printf("=== Detection finished ===\n");
}

static int starts_with(const char *s, const char *prefix)
{
	if (!s || !prefix)
		return 0;
	size_t lp = strlen(prefix);
	size_t ls = strlen(s);
	if (lp > ls)
		return 0;
	return strncmp(s, prefix, lp) == 0;
}

static int ends_with(const char *s, const char *suffix)
{
	if (!s || !suffix)
		return 0;
	size_t ls = strlen(s);
	size_t lf = strlen(suffix);
	if (lf > ls)
		return 0;
	return strcmp(s + (ls - lf), suffix) == 0;
}

static time_t parse_utc_ts(const char *date_yyyy_mm_dd,
						   const char *time_hh_mm_ss)
{
	if (!date_yyyy_mm_dd || !time_hh_mm_ss)
		return (time_t)-1;

	struct tm tmv;
	memset(&tmv, 0, sizeof(tmv));

	int Y, M, D, h, m, s;
	if (sscanf(date_yyyy_mm_dd, "%d-%d-%d", &Y, &M, &D) != 3)
		return (time_t)-1;
	if (sscanf(time_hh_mm_ss, "%d:%d:%d", &h, &m, &s) != 3)
		return (time_t)-1;

	tmv.tm_year = Y - 1900;
	tmv.tm_mon = M - 1;
	tmv.tm_mday = D;
	tmv.tm_hour = h;
	tmv.tm_min = m;
	tmv.tm_sec = s;

	// convert UTC tm --> time_t
	return timegm(&tmv);
}
