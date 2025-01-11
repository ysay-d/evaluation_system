#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>

// see Documentation/vm/pagemap.txt:
#define PFN_MASK		(~(0x1ffLLU << 55))

#define PATHSIZE		128
#define LINESIZE		256
#define PAGEMAP_CHUNK_SIZE	8
#define IDLEMAP_CHUNK_SIZE	8
#define IDLEMAP_BUF_SIZE	4096

// big enough to span 740 Gbytes:
#define MAX_IDLEMAP_SIZE	(20 * 1024 * 1024)

// from mm/page_idle.c:
#ifndef BITMAP_CHUNK_SIZE
#define BITMAP_CHUNK_SIZE	8
#endif

#ifndef PAGE_OFFSET
#define PAGE_OFFSET		0xffff880000000000LLU
#endif

// globals
int g_debug = 0;		// 1 == some, 2 == verbose
int g_activepages = 0;
int g_walkedpages = 0;
char *g_idlepath = "/sys/kernel/mm/page_idle/bitmap";
unsigned long long *g_idlebuf;
unsigned long long g_idlebufsize;

void write_to_file(FILE *file, unsigned long long start, unsigned long long end, char *filename) {
    unsigned long long memory_size = end - start;
    double memory_size_mb = (double)memory_size / (1024 * 1024);
    fprintf(file, "Filename:%s\t Range: %llx-%llx\t Memory Size: %.2f MB\t Active Pages: %d\n", filename, start, end, memory_size_mb, g_activepages);
}
/*
 * This code must operate on bits in the pageidle bitmap and process pagemap.
 * Doing this one by one via syscall read/write on a large process can take too
 * long, eg, 7 minutes for a 130 Gbyte process. Instead, I copy (snapshot) the
 * idle bitmap and pagemap into our memory with the fewest syscalls allowed,
 * and then process them with load/stores. Much faster, at the cost of some memory.
 */

int mapidle(pid_t pid, unsigned long long mapstart, unsigned long long mapend)
{
	char pagepath[PATHSIZE];
	int pagefd;
	char *line;
	unsigned long long offset, i, pagemapp, pfn, idlemapp, idlebits;
	int pagesize;
	int err = 0;
	unsigned long long *pagebuf, *p;
	unsigned long long pagebufsize;
	ssize_t len;
	
	// XXX: handle huge pages
	pagesize = getpagesize();

	pagebufsize = (PAGEMAP_CHUNK_SIZE * (mapend - mapstart)) / pagesize;
	if ((pagebuf = malloc(pagebufsize)) == NULL) {
		printf("Can't allocate memory for pagemap buf (%lld bytes)",
		    pagebufsize);
		return 1;
	}

	// open pagemap for virtual to PFN translation
	if (sprintf(pagepath, "/proc/%d/pagemap", pid) < 0) {
		printf("Can't allocate memory.");
		return 1;
	}
	if ((pagefd = open(pagepath, O_RDONLY)) < 0) {
		perror("Can't read pagemap file");
		return 2;
	}

	// cache pagemap to get PFN, then operate on PFN from idlemap
	offset = PAGEMAP_CHUNK_SIZE * mapstart / pagesize;
	if (lseek(pagefd, offset, SEEK_SET) < 0) {
		printf("Can't seek pagemap file\n");
		err = 1;
		goto out;
	}
	p = pagebuf;

	// optimized: read this in one syscall
	if (read(pagefd, p, pagebufsize) < 0) {
		perror("Read page map failed.");
		err = 1;
		goto out;
	}

	for (i = 0; i < pagebufsize / sizeof (unsigned long long); i++) {
		// convert virtual address p to physical PFN
		pfn = p[i] & PFN_MASK;
		if (pfn == 0)
			continue;

		// read idle bit
		idlemapp = (pfn / 64) * BITMAP_CHUNK_SIZE;
		if (idlemapp > g_idlebufsize) {
			printf("ERROR: bad PFN read from page map.\n");
			err = 1;
			goto out;
		}
		idlebits = g_idlebuf[idlemapp];
		if (g_debug > 1) {
			printf("R: p %llx pfn %llx idlebits %llx\n",
			    p[i], pfn, idlebits);
		}

		if (!(idlebits & (1ULL << (pfn % 64)))) {
			g_activepages++;    
		}
		g_walkedpages++;
	}

out:
	close(pagefd);

	return err;
}

int walkmaps(pid_t pid)
{
	FILE *mapsfile;
    FILE *output_file;
	char mapspath[PATHSIZE];
	char line[LINESIZE];
	size_t len = 0;
	unsigned long long mapstart, mapend;

    output_file = fopen("get_active_page_data.txt", "a");
    if (output_file == NULL) {
        perror("Can't open output file");
        return 1;
    }
    
	// read virtual mappings
	if (sprintf(mapspath, "/proc/%d/maps", pid) < 0) {
		printf("Can't allocate memory. Exiting.");
		exit(1);
	}
	if ((mapsfile = fopen(mapspath, "r")) == NULL) {
		return 1;
	}

	while (fgets(line, sizeof (line), mapsfile) != NULL) {
        char file_path[256] = {0};
		sscanf(line, "%llx-%llx", &mapstart, &mapend);
        if (sscanf(line, "%*llx-%*llx %*s %*s %*s %*s %255s", file_path) != 1) {
            strcpy(file_path, "[anno]");
        }

        char *filename = strrchr(file_path, '/');  
        if (filename) {
            filename++;  
        } else {
            filename = file_path;  
        }

		if (g_debug)
			printf("MAP %llx-%llx\n", mapstart, mapend);
		if (mapstart > PAGE_OFFSET)
			continue;	// page idle tracking is user mem only
		// if (mapidle(pid, mapstart, mapend)) {
		// 	printf("Error setting map %llx-%llx. Exiting.\n",
		// 	    mapstart, mapend);
		// }

        if (mapidle(pid, mapstart, mapend)) {
		    printf("Error setting map %llx-%llx. Exiting.\n", mapstart, mapend);
        }
        write_to_file(output_file, mapstart, mapend, filename);
        g_activepages = 0;

	}

	fclose(mapsfile);
    fclose(output_file);
	return 0;
}

int setidlemap()
{
	char *p;
	int idlefd, i;
	// optimized: large writes allowed here:
	char buf[IDLEMAP_BUF_SIZE];

	for (i = 0; i < sizeof (buf); i++)
		buf[i] = 0xff;

	// set entire idlemap flags
	if ((idlefd = open(g_idlepath, O_WRONLY)) < 0) {
		perror("Can't write idlemap file");
		exit(2);
	}
	// only sets user memory bits; kernel is silently ignored
	while (write(idlefd, &buf, sizeof(buf)) > 0) {;}

	close(idlefd);

	return 0;
}

int loadidlemap()
{
	unsigned long long *p;
	int idlefd;
	ssize_t len;

    if (g_idlebuf != NULL) {
        free(g_idlebuf);
        g_idlebuf = NULL;
    }

	if ((g_idlebuf = malloc(MAX_IDLEMAP_SIZE)) == NULL) {
		printf("Can't allocate memory for idlemap buf (%d bytes)",
		    MAX_IDLEMAP_SIZE);
		exit(1);
	}

	// copy (snapshot) idlemap to memory
	if ((idlefd = open(g_idlepath, O_RDONLY)) < 0) {
		perror("Can't read idlemap file");
		exit(2);
	}
	p = g_idlebuf;
	// unfortunately, larger reads do not seem supported
	while ((len = read(idlefd, p, IDLEMAP_CHUNK_SIZE)) > 0) {
		p += IDLEMAP_CHUNK_SIZE;
		g_idlebufsize += len;
	}
	close(idlefd);

    // printf("Idle map content:\n");
	// for (unsigned long long *ptr = g_idlebuf; ptr < g_idlebuf + g_idlebufsize / sizeof(unsigned long long); ptr++) {
	// 	printf("%llx ", *ptr);
	// }
	//printf("\n");

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	double duration, mbytes;
	static struct timeval ts1, ts2, ts3, ts4;
	unsigned long long set_us, read_us, dur_us, slp_us, est_us;
	FILE *output_file;
	
	output_file = fopen("get_active_page_data.txt", "w");
    if (output_file == NULL) {
        perror("Can't open output file");
        return 1;
    }
    fclose(output_file);

	// options
	if (argc < 3) {
		printf("USAGE: wss PID duration(s)\n");
		exit(0);
	}	
	pid = atoi(argv[1]);
	duration = atof(argv[2]);
	if (duration < 0.01) {
		printf("Interval too short. Exiting.\n");
		return 1;
	}
	printf("Watching PID %d page references per %.2f seconds...\n",
	    pid, duration);

	// set idle flags
	gettimeofday(&ts1, NULL);

	// sleep
	gettimeofday(&ts2, NULL);
	usleep((int)(duration * 500000));
	gettimeofday(&ts3, NULL);

	// read idle flags
    int f = 5;
    while(f--){
        usleep((int)(duration * 1000000));
        setidlemap();
	    loadidlemap();
	    if(walkmaps(pid)){
            break;
        }
    }


	gettimeofday(&ts4, NULL);

	// calculate times
	set_us = 1000000 * (ts2.tv_sec - ts1.tv_sec) +
	    (ts2.tv_usec - ts1.tv_usec);
	slp_us = 1000000 * (ts3.tv_sec - ts2.tv_sec) +
	    (ts3.tv_usec - ts2.tv_usec);
	read_us = 1000000 * (ts4.tv_sec - ts3.tv_sec) +
	    (ts4.tv_usec - ts3.tv_usec);
	dur_us = 1000000 * (ts4.tv_sec - ts1.tv_sec) +
	    (ts4.tv_usec - ts1.tv_usec);
	est_us = dur_us - (set_us / 2) - (read_us / 2);
	if (g_debug) {
		printf("set time  : %.3f s\n", (double)set_us / 1000000);
		printf("sleep time: %.3f s\n", (double)slp_us / 1000000);
		printf("read time : %.3f s\n", (double)read_us / 1000000);
		printf("dur time  : %.3f s\n", (double)dur_us / 1000000);
		// assume getpagesize() sized pages:
		printf("referenced: %d pages, %d Kbytes\n", g_activepages,
		    g_activepages * getpagesize());
		printf("walked    : %d pages, %d Kbytes\n", g_walkedpages,
		    g_walkedpages * getpagesize());
	}

	// assume getpagesize() sized pages:
	mbytes = (g_activepages * getpagesize()) / (1024 * 1024);

	return 0;
}
