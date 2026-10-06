#include "audit_logger.h"

FILE *
fopen(const char *path, const char *mode)
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char *, const char *);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = original_fopen(path, mode);

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	// open log file
	if (path && strcmp(path, "/tmp/access_audit.log") == 0)
	{
		return original_fopen(path, mode);
	}

	// stat for file existence
	struct stat st;
	int existed_before = 0;
	if (path && stat(path, &st) == 0)
	{
		existed_before = 1;
	}

	// 0=create 1=open
	int operation = existed_before ? 1 : 0;

	// denied check
	int denied = 0;

	if (path && existed_before && mode)
	{
		// r
		if (strchr(mode, 'r') && !strchr(mode, '+'))
		{
			if (euidaccess(path, R_OK) == -1)
				denied = 1;
		}

		// w, w+, a check
		if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'))
		{
			if (euidaccess(path, W_OK) == -1)
				denied = 1;
		}
	}
	else
	{
		/* Δεν υπήρχε πριν → attempt creation (operation = 0).
		 * Αν φάμε EACCES/EPERM μετά, θα βάλουμε denied = 1.
		 */
	}

	// fopen fial check dikaiomata
	if (!original_fopen_ret)
	{
		if (errno == EACCES || errno == EPERM)
		{
			denied = 1;
		}
	}

	if (!path)
	{
		return original_fopen_ret;
	}

	char abs_path[PATH_MAX];
	if (realpath(path, abs_path) == NULL)
	{
		strncpy(abs_path, path, PATH_MAX - 1);
		abs_path[PATH_MAX - 1] = '\0';
	}

	// date, time
	time_t now = time(NULL);
	struct tm utc;
	gmtime_r(&now, &utc);

	char date_str[11];
	char time_str[9];

	snprintf(date_str, sizeof(date_str), "%04d-%02d-%02d",
			 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday);

	snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d",
			 utc.tm_hour, utc.tm_min, utc.tm_sec);

	// sha-256
	char hash_hex[65];
	hash_hex[0] = '\0';

	if (!denied && original_fopen_ret)
	{
		int fd = open(abs_path, O_RDONLY);
		if (fd >= 0)
		{
			EVP_MD_CTX *md = EVP_MD_CTX_new();
			unsigned char hash[EVP_MAX_MD_SIZE];
			unsigned int hash_len = 0;
			unsigned char buffer[4096];

			EVP_DigestInit_ex(md, EVP_sha256(), NULL);

			ssize_t n;
			while ((n = read(fd, buffer, sizeof(buffer))) > 0)
			{
				EVP_DigestUpdate(md, buffer, n);
			}

			EVP_DigestFinal_ex(md, hash, &hash_len);

			close(fd);
			EVP_MD_CTX_free(md);

			for (unsigned int i = 0; i < hash_len; i++)
			{
				sprintf(hash_hex + i * 2, "%02x", hash[i]);
			}
			hash_hex[hash_len * 2] = '\0';
		}
		else
		{
			strcpy(hash_hex, "-");
		}
	}
	else
	{
		strcpy(hash_hex, "-");
	}

	// write in /tmp/access_audit.log
	int log_fd = open("/tmp/access_audit.log",
					  O_WRONLY | O_CREAT | O_APPEND, 0666);

	if (log_fd >= 0)
	{
		uid_t uid = getuid();
		pid_t pid = getpid();

		char line[2048];
		int len = snprintf(
			line, sizeof(line),
			"%d|%d|%s|%s|%s|%d|%d|%s\n",
			(int)uid,
			(int)pid,
			abs_path,
			date_str,
			time_str,
			operation,
			denied,
			hash_hex);

		if (len > 0)
		{
			write(log_fd, line, len);
		}
		close(log_fd);
	}

	return original_fopen_ret;
}

size_t
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = original_fwrite(ptr, size, nmemb, stream);

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	// nothikng written
	if (original_fwrite_ret == 0)
	{
		return original_fwrite_ret;
	}

	// find path file via /proc/self/fd
	int fd_data = fileno(stream);
	if (fd_data < 0)
	{
		return original_fwrite_ret;
	}

	char link_path[64];
	char abs_path[PATH_MAX];

	snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd_data);
	ssize_t len_path = readlink(link_path, abs_path, sizeof(abs_path) - 1);
	if (len_path == -1)
	{
		return original_fwrite_ret;
	}
	abs_path[len_path] = '\0';

	if (strcmp(abs_path, "/tmp/access_audit.log") == 0)
	{
		return original_fwrite_ret;
	}

	// date, time
	time_t now = time(NULL);
	struct tm utc;
	gmtime_r(&now, &utc);

	char date_str[11];
	char time_str[9];

	snprintf(date_str, sizeof(date_str), "%04d-%02d-%02d",
			 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday);
	snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d",
			 utc.tm_hour, utc.tm_min, utc.tm_sec);

	// sha-256
	char hash_hex[65];
	hash_hex[0] = '\0';

	int fd_hash = open(abs_path, O_RDONLY);
	if (fd_hash >= 0)
	{
		EVP_MD_CTX *md = EVP_MD_CTX_new();
		unsigned char hash[EVP_MAX_MD_SIZE];
		unsigned int hash_len = 0;
		unsigned char buffer[4096];

		EVP_DigestInit_ex(md, EVP_sha256(), NULL);
		ssize_t n;
		while ((n = read(fd_hash, buffer, sizeof(buffer))) > 0)
		{
			EVP_DigestUpdate(md, buffer, n);
		}
		EVP_DigestFinal_ex(md, hash, &hash_len);

		close(fd_hash);
		EVP_MD_CTX_free(md);

		for (unsigned int i = 0; i < hash_len; i++)
		{
			sprintf(hash_hex + i * 2, "%02x", hash[i]);
		}
		hash_hex[hash_len * 2] = '\0';
	}
	else
	{
		strcpy(hash_hex, "-");
	}

	// op=2
	int log_fd = open("/tmp/access_audit.log",
					  O_WRONLY | O_CREAT | O_APPEND, 0666);
	if (log_fd >= 0)
	{
		uid_t uid = getuid();
		pid_t pid = getpid();
		int operation = 2; // write
		int denied = 0;	   // if we reached write we have access

		char line[2048];
		int len = snprintf(
			line, sizeof(line),
			"%d|%d|%s|%s|%s|%d|%d|%s\n",
			(int)uid,
			(int)pid,
			abs_path,
			date_str,
			time_str,
			operation,
			denied,
			hash_hex);

		if (len > 0)
		{
			write(log_fd, line, len);
		}
		close(log_fd);
	}

	return original_fwrite_ret;
}

int fclose(FILE *stream)
{
	int original_fclose_ret;
	int (*original_fclose)(FILE *);

	/* call the original fclose function */
	original_fclose = dlsym(RTLD_NEXT, "fclose");
	original_fclose_ret = original_fclose(stream);

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */

	int fd_data = fileno(stream);
	char abs_path[PATH_MAX];
	int have_path = 0;

	if (fd_data >= 0)
	{
		char link_path[64];
		snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd_data);
		ssize_t len_path = readlink(link_path, abs_path, sizeof(abs_path) - 1);
		if (len_path != -1)
		{
			abs_path[len_path] = '\0';
			have_path = 1;
		}
	}

	if (!have_path || strcmp(abs_path, "/tmp/access_audit.log") == 0)
	{
		return original_fclose_ret;
	}

	// date, time
	time_t now = time(NULL);
	struct tm utc;
	gmtime_r(&now, &utc);

	char date_str[11];
	char time_str[9];

	snprintf(date_str, sizeof(date_str), "%04d-%02d-%02d",
			 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday);
	snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d",
			 utc.tm_hour, utc.tm_min, utc.tm_sec);

	// sha-256
	char hash_hex[65];
	hash_hex[0] = '\0';

	int fd_hash = open(abs_path, O_RDONLY);
	if (fd_hash >= 0)
	{
		EVP_MD_CTX *md = EVP_MD_CTX_new();
		unsigned char hash[EVP_MAX_MD_SIZE];
		unsigned int hash_len = 0;
		unsigned char buffer[4096];

		EVP_DigestInit_ex(md, EVP_sha256(), NULL);
		ssize_t n;
		while ((n = read(fd_hash, buffer, sizeof(buffer))) > 0)
		{
			EVP_DigestUpdate(md, buffer, n);
		}
		EVP_DigestFinal_ex(md, hash, &hash_len);

		close(fd_hash);
		EVP_MD_CTX_free(md);

		for (unsigned int i = 0; i < hash_len; i++)
		{
			sprintf(hash_hex + i * 2, "%02x", hash[i]);
		}
		hash_hex[hash_len * 2] = '\0';
	}
	else
	{
		strcpy(hash_hex, "-");
	}

	// op=3
	int log_fd = open("/tmp/access_audit.log",
					  O_WRONLY | O_CREAT | O_APPEND, 0666);
	if (log_fd >= 0)
	{
		uid_t uid = getuid();
		pid_t pid = getpid();
		int operation = 3; // closed
		int denied = 0;	   // not important for closing file

		char line[2048];
		int len = snprintf(
			line, sizeof(line),
			"%d|%d|%s|%s|%s|%d|%d|%s\n",
			(int)uid,
			(int)pid,
			abs_path,
			date_str,
			time_str,
			operation,
			denied,
			hash_hex);

		if (len > 0)
		{
			write(log_fd, line, len);
		}
		close(log_fd);
	}

	return original_fclose_ret;
}