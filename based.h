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
#include <unistd.h>

#include "dict.h"

#define BASE_NAME "based"
#define BASE_VERSION "0.0.3"

#define BASE_DEFAULT_LOG_FILE "./log"
#define BASE_DEFAULT_HTTP_ADDR "127.0.0.1"
#define BASE_DEFAULT_HTTP_PORT "8080"

struct base_peer {
	char *log_file;
	int log_fd;
	off_t log_off;
	dict_t index;
	char *http_addr;
	in_port_t http_port;
	struct evhttp *httpd;
};

struct base_entry {
	uint32_t head_len;
	uint32_t content_len;
	// headers
	// content
};
#define BASE_ENTRY_HEAD_LEN_MAX    UINT32_MAX
#define BASE_ENTRY_CONTENT_LEN_MAX UINT32_MAX

struct base_header {
	uint16_t type;
	uint16_t len;
	// value
};
#define BASE_HEADER_TYPE_MAX UINT16_MAX
#define BASE_HEADER_LEN_MAX UINT16_MAX
#define BASE_HEADER_TYPE_ID 1

struct base_extent {
	off_t off;
	size_t len;
};

#endif
