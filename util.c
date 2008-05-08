#include "util.h"

int
util_pread_all(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t res;
	size_t read = 0;
	while(read < count) {
		if ((res = pread(fd, buf + read, count - read,
				 offset + read)) == -1)
			return -1;
		else
			read += res;
	}
	return 0;
}

/* Adapted from Linux Journal, September 2007. */
int
util_writev_all(int fd, struct iovec *vec, int count)
{
	int i = 0;
	ssize_t res;
	size_t written = 0;
        while (i < count) {
		if ((res = writev(fd, &vec[i], count - i)) == -1)
			return -1;
                written += res;
                while (res > 0) {
                        if (res < vec[i].iov_len) {
                                vec[i].iov_base = 
					(char *) vec[i].iov_base + res;
                                vec[i].iov_len -= res;
                                res = 0;
                        } else {
                                res -= vec[i].iov_len;
                                ++i;
                        }
                }
        }
        return 0;
}
