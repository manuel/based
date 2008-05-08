#ifndef _UTIL_H
#define _UTIL_H

#include <sys/uio.h>

int
util_pread_all(int, void *, size_t, off_t);

int
util_writev_all(int, struct iovec *, int);

#endif
