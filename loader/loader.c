/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction old_action;

/* in this array I set the already mapped segments */
static int *mapped;

/* file descriptor */
static int file_desc;

static void handler(int signum, siginfo_t *info, void *context)
{
	/* check if the signal is a SIGSEGV one */
	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	/* declare auxiliary variables */
	char *addr, *mem;
	int res, i, segment = -1, zero;
	int page_size = getpagesize();

	void *addr_segment, *zero_address, *bss_address;
	int permision, offset;

	/* get the address where the handler triggered */
	addr = info->si_addr;

	/* get the segment */
	for (i = 0; i < exec->segments_no; i++) {
		if (addr >= ((char *) exec->segments[i].vaddr) &&
			addr < ((char *) exec->segments[i].vaddr + exec->segments[i].mem_size))
			segment = i;
	}

	/*
	 * if the address is not in a known segment,
	 * then we call the old handler
	 */
	if (segment == -1) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	/* count the pages from the given segment */
	int pages = exec->segments[segment].mem_size / page_size;

	if (exec->segments[segment].mem_size % page_size != 0)
		pages++;

	/*
	 * check if the address is in a mapped segment
	 * if so, then call the old handler, otherwise,
	 * map the segment
	 */
	if (mapped[segment] == pages) {
		old_action.sa_sigaction(signum, info, context);
	} else {
		/* initialize auxiliary variables */
		permision = exec->segments[segment].perm;
		offset = exec->segments[segment].offset + mapped[segment] * page_size;
		addr_segment = (void *) exec->segments[segment].vaddr + mapped[segment] * page_size;

		/*
		 * call the map function, we operate on the file,
		 * so I am not using the default permisions of the
		 * segment as they do not allow writing
		 */
		mem = mmap(addr_segment, page_size,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, file_desc, offset);
		/* count page as being mapped */
		mapped[segment]++;

		if (mem == -1)
			return;

		if (pages == mapped[segment]) {
			/* if it is the last page of the segment and if
			 * there are the file size is less than the mem_size
			 * then we should fill the difference with zeros
			 */
			zero = exec->segments[segment].mem_size - exec->segments[segment].file_size;
			if (zero > 0) {
				zero = exec->segments[segment].mem_size - (mapped[segment] - 1) * page_size;
				bss_address = exec->segments[segment].vaddr + (mapped[segment] - 1) * page_size;
				memset(bss_address, 0x00, zero);
			}
		} else {
			/*
			 * Here is basically the same situation as above
			 * but, now I compute the position of the address
			 * where we should begin filling with zeros by
			 * making use of the file_size
			 */
			zero = mapped[segment] * page_size - exec->segments[segment].file_size;
			if (zero < page_size) {
				bss_address = exec->segments[segment].vaddr + exec->segments[segment].file_size;
				if (zero > 0)
					memset(bss_address, 0x00, zero);
			}
		}

		/*
		 * change the permision for that particular page
		 * to the expected one
		 */
		res = mprotect(addr_segment, page_size, permision);
		if (res == -1)
			exit(-1);
	}

}

int so_init_loader(void)
{
	/* Initialize loader */
	struct sigaction action;
	int rc;

	/* set the custom handler */
	action.sa_sigaction = handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);

	return rc;
}

int so_execute(char *path, char *argv[])
{
	int res, i, page_no;
	void *address;

	/* get the size of a page */
	int page_size = getpagesize();

	/* open the file to be executed */
	file_desc = open(path, O_RDONLY);

	/* parse file */
	exec = so_parse_exec(path);

	if (!exec)
		return -1;

	/*
	 * alloc the vector that counts the mapped pages
	 * of the segments
	 */
	mapped = calloc(exec->segments_no, sizeof(int));

	so_start_exec(exec, argv);

	/* unmap */
	for (i = 0; i < exec->segments_no; i++) {
		address = (void *) exec->segments[i].vaddr;
		/* count the number of pages that need to be unmapped */
		page_no = exec->segments[i].mem_size / page_size;
		if (exec->segments[i].mem_size % page_size > 0)
			page_no++;
		/* call munmap */
		res = munmap(address, page_no * page_size);
		if (res < 0)
			return -1;
	}

	return -1;
}

