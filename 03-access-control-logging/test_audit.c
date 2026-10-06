#include <stdio.h>
#include <string.h>

int main()
{

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1",
							 "file_2", "file_3", "file_4",
							 "file_5", "file_6", "file_7",
							 "file_8", "file_9"};

	/* example source code */

	for (i = 0; i < 10; i++)
	{

		file = fopen(filenames[i], "w+");
		if (file == NULL)
			printf("fopen error\n");
		else
		{
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	// extra modifications
	for (i = 0; i < 10; i++)
	{

		file = fopen(filenames[i], "w+");
		if (file == NULL)
		{
			printf("fopen error on %s (second round)\n", filenames[i]);
		}
		else
		{
			bytes = fwrite("APPEND\n", 1, 7, file);
			(void)bytes;
			fclose(file);
		}
	}

	// denied file
	FILE *file2 = fopen("file_test", "w");
	if (file2 != NULL)
	{
		fprintf(file2, "this file will become unreadable\n");
		fclose(file2);
	}

	chmod("file_test", 0000); // remove permission

	file2 = fopen("file_test", "r");
	if (file2 == NULL)
	{
		printf("fopen denied on file_test (as expected)\n");
	}
	else
	{
		fclose(file2);
	}

	// test -s
	const char *deny_files[] = {
		"deny_0",
		"deny_1",
		"deny_2",
		"deny_3",
		"deny_4"};

	int n_deny = sizeof(deny_files) / sizeof(deny_files[0]);

	for (i = 0; i < n_deny; i++)
	{

		FILE *df = fopen(deny_files[i], "w");
		if (df != NULL)
		{
			fprintf(df, "this will also become unreadable\n");
			fclose(df);
		}

		chmod(deny_files[i], 0000);

		df = fopen(deny_files[i], "r");
		if (df == NULL)
		{
			printf("fopen denied on %s (as expected)\n", deny_files[i]);
		}
		else
		{
			fclose(df);
		}
	}

	printf("test_audit finished.\n");
	return 0;
}
