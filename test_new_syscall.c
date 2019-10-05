#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <linux/kernel.h>
#include <stdlib.h>
#include <errno.h> /* for errno macro */
#include <string.h> /* for error string */

/* buf
 * It should point to a buffer to store the process tree's data.
 * The data stored inside the buffer should be in BFS order:
 * processes at a higher level (level 0 is considered to be higher than level 10)
 * should appear before processes at a lower level.
 *
 * nr
 * represents the size of this buffer (number of entries).
 * The system call copies at most that many entries of the process tree
 * data to the buffer and stores the number of entries actually copied in nr.
 *
 * root_pid
 * represents the pid of the root of the subtree you are required to traverse.
 * Note that information of nodes outside of this subtree shouldn't be put into buf.
 *
 * Return value: Your system call should return 0 on success.
 *
 * Signature:
 * int ptree(struct prinfo *buf, int *nr, int root_pid);
 */

struct prinfo {
	pid_t parent_pid;       /* process id of parent */
	pid_t pid;              /* process id */
	long state;             /* current state of process */
	uid_t uid;              /* user id of process owner */
	char comm[16];          /* name of program executed */
	int level;              /* level of this process in the subtree */
};

// defined in syscall table as 333, in unistd.h as 292
// will return 11 from kernel/sys.c
int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: must provide parameter PID in number form\n");
		printf("Example: %s 2\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	struct prinfo *buf = NULL; /* buffer to hold results with processes */
	int *nr = NULL;	/* number of processes to request */
	int root_pid = atoi(argv[1]); /* PID to start the process list iteration */
	printf("root_pid is %d\n", root_pid);
	/* Set arbitrary number of processes to request */
	int number_of_processes = 200;
	nr = &number_of_processes; /* assign pointer to our numerical value */

	/* create buffer */
	buf = malloc(sizeof(struct prinfo) * number_of_processes);

	/* Verify we have a buffer assigned */
	if (buf == NULL) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
		// TODO: shall we handle it in a different way, other than terminate?
	}

	/* testing call of syscall with parameters */
	long int sc = syscall(333, buf, nr, root_pid);
	printf("System Call 333, ptree: %ld\n", sc);
	printf("Our nr is now: %d\n", *nr);

	/* For each process, you must use the following format for program output: */
	int i;

	for (i = 0; i < *nr; i++) {
		printf("%s,%d,%d,%ld,%d\n", buf[i].comm, buf[i].pid,
			   buf[i].parent_pid, buf[i].state, buf[i].level);
	}



	/* cleanup */
	free(buf);
	return 0;

}

