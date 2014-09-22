#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>

#define FNV1A_OFFSET_BASIS 14695981039346656037UL
#define FNV1A_PRIME 1099511628211UL

int main(int argc, char *argv[]) 
{
	uint8_t *cptr, *file;
	uint64_t tmphash, hash = FNV1A_OFFSET_BASIS, *data;
	struct stat s;
	int fd;

	// argv[1] - str for hash
	// argv[2] - file
	if (argc != 3) {
		return 1;
	}

	for (cptr=(uint8_t*)argv[1]; *cptr; cptr++) {
		hash ^= (uint64_t)*cptr;
		hash = hash * FNV1A_PRIME;
	}

	fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		return 1;
	}

	if (fstat(fd, &s) < 0) {
		return 1;
	}

	file = malloc(s.st_size + (8-(s.st_size%8)));
	if (file == NULL) {
		return 1;
	}

	if (read(fd, file, s.st_size) != s.st_size) {
		free(file);
		return 1;
	}

	close(fd);
	tmphash = hash;
	for(data = (uint64_t *)file; (void*)data < (void*)(file+s.st_size); data++) {
		*data ^= tmphash;
		tmphash *= FNV1A_PRIME;
	}

	write(STDOUT_FILENO, file, s.st_size);
	free(file);	
	return 0;
}

