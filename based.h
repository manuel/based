#ifndef _BASED_H
#define _BASED_H

#include <err.h>
#include <errno.h>
#include <evhttp.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "dict.h"
#include "pool.h"
#include "util.h"

#define BASE_NAME "based"
#define BASE_VERSION "0.0.3"

#define BASE_DEFAULT_LOG_FILE "./log"
#define BASE_DEFAULT_HTTP_ADDR "127.0.0.1"
#define BASE_DEFAULT_HTTP_PORT "8080"

/* Requires libevent 1.4.3 plus sendfile patches:
   http://monkeymail.org/archives/libevent-users/2008-May/thread.html */
#define BASE_USE_SENDFILE

struct base_peer {
	char *log_file;
	int log_fd;
	off_t log_off;
	dict_t index;
	char *http_addr;
	in_port_t http_port;
	struct evhttp *httpd;
	struct pool pool;
};

/* 32/64-bit plan: entry lengths should always be representable using
   ssize_t, which means theoretical max lengths are 2^31-1 on 32-bit
   and 2^63-1 on 64-bit.  The file format supports up to 2^48-1 bytes
   of entry length, but currently we artificially restrict it to
   2^31-1 so we can use size_t and off_t on 32-bit platforms.
   Furthermore, for coding convenience the content length is
   restricted to (max entry length) - (max head length), even though
   the file format supports content lengths up to (max entry length) -
   8 if the head is empty.  This restriction could easily be lifted if
   required. */

struct base_entry {
	uint64_t len:48, head_len:16;
	// headers
	// content
};
#define BASE_ENTRY_LEN_MAX ((1U<<31)-1)
#define BASE_ENTRY_HEAD_LEN_MAX ((1U<<16)-1)
#define BASE_ENTRY_CONTENT_LEN_MAX \
(BASE_ENTRY_LEN_MAX - BASE_ENTRY_HEAD_LEN_MAX)

struct base_header {
	uint16_t type:4, len:12;
	// value
};
#define BASE_HEADER_TYPE_MAX ((1U<<4)-1)
#define BASE_HEADER_LEN_MAX ((1U<<12)-1)
#define BASE_HEADER_TYPE_ID 1

struct base_extent {
	off_t off;
	uint64_t len:48, head_len:16;
};

#endif
