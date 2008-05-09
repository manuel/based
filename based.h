#ifndef BASED_H
#define BASED_H

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

#define BASE_NAME "based"
#define BASE_VERSION "0.0.4 alpha"

#define BASE_DEFAULT_LOG_FILE "./log"
#define BASE_DEFAULT_HTTP_ADDR "127.0.0.1"
#define BASE_DEFAULT_HTTP_PORT "8080"

/* Requires libevent 1.4.3 plus sendfile patches:
   http://monkeymail.org/archives/libevent-users/2008-May/thread.html */
#define BASE_USE_SENDFILE 0

struct base_peer {
	char *log_file;
	int log_fd;
	off_t log_off;
	dict_t index;
	char *http_addr;
	in_port_t http_port;
	struct evhttp *httpd;
	struct pool pool;     // For allocations during writes.
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

/* Headers are small items of data associated with an entry.  For
   example, an entry's ID is stored as a header, BASE_H_ID.  A header
   has a type code, a length, and binary value. */
struct base_header {
	uint16_t type:4, len:12;
	// value
};
#define BASE_HEADER_TYPE_MAX ((1U<<4)-1)
#define BASE_HEADER_LEN_MAX ((1U<<12)-1)

/* The ID header stores the document ID of an entry.  It is stored as
   a NULL-terminated string for easy interop with C string
   functions. */
#define BASE_H_ID 1

/* The entry type header is used for some kinds of entries, such as
   delete entries.  Normal put entries have no type, simply because
   they are so common.  The value of the entry type header is a single
   uint8_t. */
#define BASE_H_ENTRY_TYPE 2
const uint8_t BASE_ENTRY_TYPE_DELETE = 1;

/* Currently, libevent is limited to receiving GET and POST requests,
   so one has to send an X-Override header with the value DELETE in a
   POST request to delete an entry. */
#define BASE_HTTP_OVERRIDE "X-Override"
#define BASE_HTTP_DELETE "DELETE"

/* The index maps document IDs to extents, which record the position
   of the entry with that ID in the log file.  When an entry is
   deleted, it is simply removed from the index. */
struct base_extent {
	off_t off;
	uint64_t len:48, head_len:16;
};

#endif
