/*
	fuzz_replay.c:	run a fuzz target over a corpus, without libFuzzer.

	Linked with one of the fuzz_*.c targets, this feeds it every file
	named on the command line - each directory named is read file by
	file - or, given none, every file in the checked-in corpus the
	build points it at (FUZZ_CORPUS).  That is how `make check` keeps
	the inputs the fuzzer once found interesting passing, with the
	compiler the rest of the tree is built with.
									*/

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len);

static int replayFile(const char *path)
{
	FILE	*f = fopen(path, "rb");
	uint8_t *buf;
	long	 size;

	if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0)
	{
		fprintf(stderr, "can't read %s\n", path);
		if (f != NULL)
		{
			fclose(f);
		}

		return -1;
	}

	rewind(f);
	buf = malloc(size > 0 ? (size_t) size : 1);
	if (buf == NULL || fread(buf, 1, (size_t) size, f) != (size_t) size)
	{
		fprintf(stderr, "can't read %s\n", path);
		free(buf);
		fclose(f);
		return -1;
	}

	fclose(f);
	(void) LLVMFuzzerTestOneInput(buf, (size_t) size);
	free(buf);
	return 0;
}

/*	Returns the number of inputs replayed, or -1.			*/

static int replay(const char *path)
{
	struct stat    st;
	struct dirent *ent;
	DIR	      *dir;
	char	       child[4096];
	int	       count = 0;
	int	       rc;

	if (stat(path, &st) != 0)
	{
		fprintf(stderr, "can't find %s\n", path);
		return -1;
	}

	if (!S_ISDIR(st.st_mode))
	{
		return replayFile(path) == 0 ? 1 : -1;
	}

	if ((dir = opendir(path)) == NULL)
	{
		fprintf(stderr, "can't open %s\n", path);
		return -1;
	}

	while ((ent = readdir(dir)) != NULL)
	{
		if (ent->d_name[0] == '.')
		{
			continue;
		}

		snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
		if ((rc = replay(child)) < 0)
		{
			closedir(dir);
			return -1;
		}

		count += rc;
	}

	closedir(dir);
	return count;
}

int main(int argc, char **argv)
{
	int count = 0;
	int rc;
	int i;

	if (argc < 2)
	{
		count = replay(FUZZ_CORPUS);
		if (count < 0)
		{
			return 1;
		}
	}

	for (i = 1; i < argc; i++)
	{
		if ((rc = replay(argv[i])) < 0)
		{
			return 1;
		}

		count += rc;
	}

	/*	An empty corpus would pass without testing anything.	*/

	if (count == 0)
	{
		fprintf(stderr, "no inputs to replay\n");
		return 1;
	}

	printf("%d inputs replayed\n", count);
	return 0;
}
