#include "based.h"

static void
base_peer_usage();
static void
base_peer_configure(struct base_peer *, int argc, char **argv);
static void 
base_peer_init_httpd(struct base_peer *);
static void
base_peer_init_log(struct base_peer *);
static void
base_peer_redo_log(struct base_peer *);
static void
base_peer_http_callback(struct evhttp_request *, void *peer);
static int
base_peer_get(struct base_peer *, struct evhttp_request *);
static int
base_peer_put(struct base_peer *, struct evhttp_request *);
static int
base_peer_index_entry(struct base_peer *, struct base_entry *, off_t);
static struct base_header *
base_entry_get_header(struct base_entry *, int header_name);
static char *
base_header_get_value(struct base_header *);
static int
base_pread_all(int, void *, size_t, off_t);
static int
base_write_all(int, void *, size_t);

int
main(int argc, char **argv)
{
	struct base_peer peer;
	bzero(&peer, sizeof(struct base_peer));

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	
	printf("%s %s\n", BASE_NAME, BASE_VERSION);
	
	base_peer_configure(&peer, argc, argv);
	base_peer_init_httpd(&peer);
	base_peer_init_log(&peer);
	base_peer_redo_log(&peer);

	event_dispatch();
}

static void
base_peer_usage()
{
	fprintf(stderr, 
		"usage: based [-l log_file] [-a http_addr] [-p http_port]");
	exit(EXIT_FAILURE);
}

static void
base_peer_configure(struct base_peer *peer, int argc, char **argv)
{
	int c;
	char *arg_log_file = BASE_DEFAULT_LOG_FILE;
	char *arg_http_addr = BASE_DEFAULT_HTTP_ADDR;
	char *arg_http_port = BASE_DEFAULT_HTTP_PORT;

	while ((c = getopt(argc, argv, "l:a:p:")) != -1) {
		switch (c) {
		case 'l':
			arg_log_file = optarg;
			break;
		case 'a':
			arg_http_addr = optarg;
			break;
		case 'p':
			arg_http_port = optarg;
			break;
		default:
			base_peer_usage();
		}
	}

	peer->log_file = arg_log_file;
	peer->http_addr = arg_http_addr;
	
	errno = 0;
	unsigned long http_port = strtoul(arg_http_port, NULL, 10);
	if (errno || (http_port > USHRT_MAX))
		errx(EXIT_FAILURE, "Invalid HTTP port");
	peer->http_port = http_port;

	printf("Log file %s\n", peer->log_file);
	printf("HTTP address %s\n", peer->http_addr);
	printf("HTTP port %d\n", peer->http_port);
}

static void
base_peer_init_httpd(struct base_peer *peer)
{
	if (!event_init())
		errx(EXIT_FAILURE, "Cannot initialize libevent");

	if (!(peer->httpd = evhttp_new(NULL)))
		errx(EXIT_FAILURE, "Cannot create HTTP server");

	if (evhttp_bind_socket(peer->httpd, peer->http_addr, peer->http_port))
		errx(EXIT_FAILURE, "Cannot bind HTTP server");

	evhttp_set_gencb(peer->httpd, base_peer_http_callback, peer);
}

static void
base_peer_init_log(struct base_peer *peer)
{
	if ((peer->log_fd = open(peer->log_file,
				 O_RDWR | O_CREAT | O_SYNC | O_APPEND,
				 S_IRUSR | S_IWUSR)) == -1)
		err(EXIT_FAILURE, "Cannot open log file");

	dict_init(&peer->log_index, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) strcmp);

	peer->log_off = 0;
}

/* Mmap the log file, loop through the entries in it, and add each to
   the index. */

static void
base_peer_redo_log(struct base_peer *peer)
{
	struct stat stat;
	bzero(&stat, sizeof(struct stat));
	if (fstat(peer->log_fd, &stat) == -1)
		err(EXIT_FAILURE, "Cannot stat log file");
	
	char *log;
	off_t log_len = stat.st_size;
	if (log_len == 0) return;
	if (!(log = mmap(NULL, log_len, PROT_READ, MAP_SHARED,
			 peer->log_fd, 0)))
		err(EXIT_FAILURE, "Cannot map log file");

	struct base_entry *entry;
	char *entry_ptr;
	size_t log_off = 0;
	while(log_off < log_len) {
		entry_ptr = log + log_off;
		entry = (struct base_entry *) entry_ptr;
		if (base_peer_index_entry(peer, entry, log_off) == -1)
			errx(EXIT_FAILURE, "Cannot index entry");
		log_off += (entry->head_len + entry->content_len); // hm...
	}

	peer->log_off = log_off;

	if (munmap(log, log_len) == -1)
		warn("Cannot unmap log file");
}

static void
base_peer_http_callback(struct evhttp_request *req, void *arg)
{
	struct base_peer *peer = (struct base_peer *) arg;
	
	switch (req->type) {
	case EVHTTP_REQ_GET:
		if (base_peer_get(peer, req) == 0) return;
	case EVHTTP_REQ_POST:
		if (base_peer_put(peer, req) == 0) return;
	}

	evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
}

/* Lookup the document's extent in the index, snarf the doc into a
   buffer, and hand it off to libevent for sending to the client. */

static int
base_peer_get(struct base_peer *peer, struct evhttp_request *req)
{
	char *id = req->uri;
	dnode_t *dnode;
	if (!id) return -1;
	if (dnode = dict_lookup(&peer->log_index, id)) {
		struct base_extent *extent;
		char *buf;
		struct base_entry *entry;
		char *content;
		extent = (struct base_extent *) dnode_get(dnode);
		if (!(buf = malloc(extent->len)))
			return -1;
		if (base_pread_all(peer->log_fd, buf, extent->len, extent->off) == -1) {
			free(buf);
			return -1;
		}
		entry = (struct base_entry *) buf;
		content = buf + entry->head_len;
		evbuffer_add(req->output_buffer, content, entry->content_len);
		free(buf);
		evhttp_send_reply(req, HTTP_OK, "OK", NULL);
		return 0;
	} else {
		evhttp_send_error(req, 404, "Not Found");
		return 0;
	}
}

/* Construct an entry with an ID header and the user-supplied content,
   write it to the log file and add it to the index.  If write()
   fails, we're hosed.  (Yes, this will be improved.) */

static int
base_peer_put(struct base_peer *peer, struct evhttp_request *req)
{
	char *content_buf = EVBUFFER_DATA(req->input_buffer);
	size_t content_len = EVBUFFER_LENGTH(req->input_buffer);
	if (!content_buf) return -1;
	if (content_len > BASE_ENTRY_CONTENT_LEN_MAX) return -1;

	char *id = req->uri;
	size_t id_len = strlen(id);
	if (!id) return -1;
	if ((id_len == 0) || (id_len > BASE_HEADER_VALUE_LEN_MAX)) return -1;
	
	char *head_buf;
	size_t head_len = 
		sizeof(struct base_entry) +
		sizeof(struct base_header) +
		id_len + 1;
	if (head_len > BASE_ENTRY_HEAD_LEN_MAX) return -1;
	if (!(head_buf = malloc(head_len))) return -1;
	bzero(head_buf, head_len);

	struct base_entry *entry;
	char *entry_ptr = head_buf;
	entry = (struct base_entry *) entry_ptr;
	entry->head_len = head_len;
	entry->content_len = content_len;
	
	struct base_header *id_header;
	char *id_header_ptr = entry_ptr + sizeof(struct base_entry);
	id_header = (struct base_header *) id_header_ptr;
	id_header->name = BASE_HEADER_NAME_ID;
	id_header->value_len = id_len + 1;
	
	char *id_header_value_ptr = id_header_ptr + sizeof(struct base_header);
	memcpy(id_header_value_ptr, id, id_len);
	id_header_value_ptr[id_len] = '\0';
	
	if (base_write_all(peer->log_fd, head_buf, head_len) == -1) 
		goto err;
	if (base_write_all(peer->log_fd, content_buf, content_len) == -1) 
		goto err;

	off_t old_log_off = peer->log_off;
	peer->log_off += (head_len + content_len);

	if (base_peer_index_entry(peer, entry, old_log_off) == -1) 
		goto err;

	free(head_buf);
	evhttp_send_error(req, HTTP_OK, "OK");
	return 0;

 err:
	free(head_buf);
	return -1;
}

/* If there's already a document in the index with that ID, simply
   update the index (dictionary-) node with the extent of the new
   entry.  Otherwise we have to insert a new index node, mapping the
   ID to the extent of the new entry, which we exploit to show off a
   cool (and slightly scary, I might add) "combined allocation"
   trick. */

static int
base_peer_index_entry(struct base_peer *peer, struct base_entry *entry, off_t off)
{
	char *id;
	struct base_header *id_header;
	if (!(id_header = base_entry_get_header(entry, BASE_HEADER_NAME_ID)))
		return -1;
	id = base_header_get_value(id_header);

	struct base_extent *extent;
	dnode_t *dnode;
	if (dnode = dict_lookup(&peer->log_index, id)) {
		extent = dnode_get(dnode);
		extent->off = off;
		extent->len = entry->head_len + entry->content_len; // hm...
		return 0;
	} else {
		size_t id_len = strlen(id);
		char *combined_buf, *id_copy;
		size_t combined_buf_len = 
			sizeof(struct base_extent) + id_len + 1;
		if (!(combined_buf = malloc(combined_buf_len)))
			return -1;
		bzero(combined_buf, combined_buf_len);
		extent = (struct base_extent *) combined_buf;
		extent->off = off;
		extent->len = entry->head_len + entry->content_len; // hm...
		id_copy = combined_buf + sizeof(struct base_extent);
		memcpy(id_copy, id, id_len + 1);
		if (dict_alloc_insert(&peer->log_index, id_copy, extent)) {
			return 0;
		} else {
			free(combined_buf);
			return -1;
		}
	}
}

static struct base_header *
base_entry_get_header(struct base_entry *entry, int header_name)
{
	char *header_ptr;
	struct base_header *header;
	off_t off = sizeof(struct base_entry);
	while(off < entry->head_len) {
		header_ptr = ((char *) entry) + off;
		header = (struct base_header *) header_ptr;
		if (header->name == header_name)
			return header;
		off += (sizeof(struct base_header) + header->value_len);
	}
	return NULL;
}

static char *
base_header_get_value(struct base_header *header)
{
	return ((char *) header) + sizeof(struct base_header);
}

static int
base_pread_all(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t res;
	size_t read = 0;
	while(read < count) {
		if ((res = pread(fd, buf + read, count - read, offset + read)) == -1)
			return -1;
		else
			read += res;
	}
	return 0;
}

static int
base_write_all(int fd, void *buf, size_t count)
{
	ssize_t res;
	size_t written = 0;
	while (written < count) {
		if ((res = write(fd, buf + written, count - written)) == -1)
			return -1;
		else
			written += res;
	}
	return 0;
}
