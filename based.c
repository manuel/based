#include "based.h"

void
base_peer_usage();
void
base_peer_configure(struct base_peer *, int argc, char **argv);
void
base_peer_init(struct base_peer *);
void
base_peer_redo_log(struct base_peer *);
void
base_peer_http_callback(struct evhttp_request *, void *peer);
int
base_peer_get(struct base_peer *, struct evhttp_request *);
int
base_peer_put(struct base_peer *, struct evhttp_request *);
int
base_peer_index_entry(struct base_peer *, struct base_entry *, off_t);
int
base_peer_populate_in_headers(struct base_peer*, struct evhttp_request *, 
			      dict_t *headers);
ssize_t
base_peer_marshall_entry_head(struct base_peer *, struct base_entry **,
			      dict_t *headers, size_t content_len);
struct base_header *
base_entry_get_header(struct base_entry *, int type);
char *
base_header_get_value(struct base_header *);
int
base_pread_all(int, void *, size_t, off_t);
int
base_write_all(int, void *, size_t);

int
main(int argc, char **argv)
{
	struct base_peer peer;
	memset(&peer, 0, sizeof(struct base_peer));

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	
	printf("%s (%s)\n", BASE_NAME, BASE_VERSION);
	
	base_peer_configure(&peer, argc, argv);
	base_peer_init(&peer);
	base_peer_redo_log(&peer);

	event_dispatch();
}

void
base_peer_usage()
{
	fprintf(stderr, 
		"usage: based [-l log_file] [-a http_addr] [-p http_port]");
	exit(EXIT_FAILURE);
}

void
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
	if (errno || (http_port == 0) || (http_port > UINT16_MAX))
		errx(EXIT_FAILURE, "Invalid HTTP port");
	peer->http_port = http_port;

	printf("Log file %s\n", peer->log_file);
	printf("HTTP address %s\n", peer->http_addr);
	printf("HTTP port %d\n", peer->http_port);
}

void
base_peer_init(struct base_peer *peer)
{
	if ((peer->log_fd = open(peer->log_file,
				 O_RDWR | O_CREAT | O_SYNC | O_APPEND,
				 S_IRUSR | S_IWUSR)) == -1)
		err(EXIT_FAILURE, "Cannot open log file");

	dict_init(&peer->index, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) strcmp);
	
	pool_init(&peer->pool, POOL_DEFAULT_PAGE_SIZE);

	if (!event_init())
		errx(EXIT_FAILURE, "Cannot initialize libevent");

	if (!(peer->httpd = evhttp_new(NULL)))
		errx(EXIT_FAILURE, "Cannot create HTTP server");

	if (evhttp_bind_socket(peer->httpd, peer->http_addr, peer->http_port))
		errx(EXIT_FAILURE, "Cannot bind HTTP server");

	evhttp_set_gencb(peer->httpd, base_peer_http_callback, peer);
}

/* Mmap the log file, loop through the entries in it, and add each to
   the index. */
void
base_peer_redo_log(struct base_peer *peer)
{
	struct stat stat;
	memset(&stat, 0, sizeof(struct stat));
	if (fstat(peer->log_fd, &stat) == -1)
		err(EXIT_FAILURE, "Cannot stat log file");
	
	char *log;
	off_t log_len = stat.st_size;
	if (log_len == 0) return;
	if ((log = mmap(NULL, log_len, PROT_READ, MAP_SHARED,
			peer->log_fd, 0)) == MAP_FAILED)
		err(EXIT_FAILURE, "Cannot map log file");
	
	struct base_entry *entry;
	char *entry_ptr;
	off_t off = 0;
	while(off < log_len) {
		entry_ptr = log + off;
		entry = (struct base_entry *) entry_ptr;
		if (base_peer_index_entry(peer, entry, off) == -1)
			errx(EXIT_FAILURE, "Cannot index entry");
		off += base_entry_len(entry);
	}

	peer->log_off = off;

	if (munmap(log, log_len) == -1)
		warn("Cannot unmap log file");
}

void
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

/* Lookup the document's extent in the index, read the doc into a
   buffer, and hand it off to libevent for sending to the client. */
int
base_peer_get(struct base_peer *peer, struct evhttp_request *req)
{
	char *id = req->uri;
	dnode_t *dnode;
	if (!id) return -1;
	if (dnode = dict_lookup(&peer->index, id)) {
		struct base_extent *extent;
		extent = (struct base_extent *) dnode_get(dnode);

		char *buf;
		struct base_entry *entry;
		char *content;
		if (!(buf = malloc(extent->len)))
			return -1;
		if (base_pread_all(peer->log_fd, buf, extent->len, 
				   extent->off) == -1) {
			free(buf);
			return -1;
		}
		entry = (struct base_entry *) buf;
		content = buf + base_entry_head_len(entry);
		evbuffer_add(req->output_buffer, content, 
			     base_entry_content_len(entry));
		free(buf);
		evhttp_send_reply(req, HTTP_OK, "OK", NULL);

		return 0;
	} else {
		evhttp_send_error(req, 404, "Not Found");
		return 0;
	}
}

int
base_header_cmp(struct base_header *h1, struct base_header *h2)
{
	return h1->type - h2->type;
}

/* Construct an entry with an ID header and the user-supplied content,
   write it to the log file and add it to the index.  If write()
   fails, we're hosed.  (Yes, this will be improved.) */
int
base_peer_put(struct base_peer *peer, struct evhttp_request *req)
{
	char *content_buf = EVBUFFER_DATA(req->input_buffer);
	size_t content_len = EVBUFFER_LENGTH(req->input_buffer);
	if (!content_buf) return -1;
	if (content_len > BASE_ENTRY_CONTENT_LEN_MAX) return -1;

	dict_t headers;
	dict_init(&headers, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) base_header_cmp);
	dict_allow_dupes(&headers);
	if (base_peer_populate_in_headers(peer, req, &headers) == -1)
		goto err;
	
	struct base_entry *entry;
	ssize_t head_len;
	if ((head_len =
	     base_peer_marshall_entry_head(peer, &entry, 
					   &headers, content_len)) == -1)
		goto err;

	if (base_write_all(peer->log_fd, (char *) entry, head_len) == -1)
		goto err;
	if (base_write_all(peer->log_fd, content_buf, content_len) == -1)
		goto err;

	off_t old_log_off = peer->log_off;
	peer->log_off += (head_len + content_len);
	
	if (base_peer_index_entry(peer, entry, old_log_off) == -1)
		goto err;

	pool_bump(&peer->pool);
	evhttp_send_error(req, HTTP_OK, "OK");
	return 0;

 err:
	pool_bump(&peer->pool);
	return -1;
}

/* Add an entry to the index.  This is called when a new entry is PUT,
   and when we are redoing the log. -- If there's already a document
   in the index with that ID, simply update the index (dictionary-)
   node with the extent of the new entry.  Otherwise we have to insert
   a new index node, mapping the ID to the extent of the new entry. */
int
base_peer_index_entry(struct base_peer *peer, 
		      struct base_entry *entry, 
		      off_t off)
{
	char *id;
	struct base_header *id_header;
	if (!(id_header = base_entry_get_header(entry, BASE_HEADER_TYPE_ID)))
		return -1;
	id = base_header_get_value(id_header);

	struct base_extent *extent;
	dnode_t *dnode;
	if (dnode = dict_lookup(&peer->index, id)) {
		extent = dnode_get(dnode);
		extent->off = off;
		extent->len = base_entry_len(entry);
		extent->head_len = base_entry_head_len(entry);
		return 0;
	} else {
		if (dict_isfull(&peer->index)) return -1;
		// Use a combined buffer for both the extent and the ID copy.
		size_t id_len = base_header_len(id_header);
		char *combined_buf, *id_copy;
		size_t combined_buf_len =
			sizeof(struct base_extent) + id_len + 1;
		if (!(combined_buf = malloc(combined_buf_len)))
			return -1;
		memset(combined_buf, 0, combined_buf_len);
		extent = (struct base_extent *) combined_buf;
		extent->off = off;
		extent->len = base_entry_len(entry);
		extent->head_len = base_entry_head_len(entry);
		id_copy = combined_buf + sizeof(struct base_extent);
		memcpy(id_copy, id, id_len + 1);
		if (dict_alloc_insert(&peer->index, id_copy, extent)) {
			return 0;
		} else {
			free(combined_buf);
			return -1;
		}
	}
}

/* Fill the headers dictionary with headers that should be written to
   disk for the entry corresponding to a HTTP PUT request.  New memory
   for the headers should be allocated from the pool; it is also to OK
   to reference data in the request, as the headers will be written
   before the request is destroyed. */
int
base_peer_populate_in_headers(struct base_peer* peer,
			      struct evhttp_request *req, 
			      dict_t *headers)
{
	char *id = req->uri;
	size_t id_len = strlen(id);
	struct base_header *id_header;
	dnode_t *id_dnode;
	if (!id) return -1;
	if ((id_len == 0) || (id_len > (BASE_HEADER_LEN_MAX - 1)))  return -1;
	if (!(id_dnode = palloc(&peer->pool, sizeof(dnode_t)))) return -1;
	if (!(id_header = palloc(&peer->pool, sizeof(struct base_header))))
		return -1;
	id_header->type = BASE_HEADER_TYPE_ID;
	id_header->len = id_len + 1;
	dnode_init(id_dnode, id);
	dict_insert(headers, id_dnode, id_header);
}

/* Create the binary representation of the head of an entry so that
   the content can be written after it.  The memory is allocated from
   the pool. */
ssize_t
base_peer_marshall_entry_head(struct base_peer *peer, 
			      struct base_entry **out_entry,
			      dict_t *headers, 
			      size_t content_len)
{
	// Get the total length of the head, including headers
	size_t head_len = sizeof(struct base_entry);
	const struct base_header *header;
	dnode_t *iter = dict_first(headers);
	while(iter) {
		header = dnode_getkey(iter);
		head_len += (sizeof(struct base_header) + header->len);
		if (iter == dict_last(headers)) break;
		iter = dict_next(headers, iter);
	}
	
	struct base_entry *entry;
	if (!(entry = palloc(&peer->pool, head_len))) 
		return -1;
	entry->head_len = head_len;
	entry->len = head_len + content_len;
	// todo: overflow checks
	
	// Serialize the headers
	char *dest = ((char *) entry) + sizeof(struct base_entry);
	struct base_header *dest_header;
	char *dest_value, *value;
	iter = dict_first(headers);
	while(iter) {
		header = dnode_getkey(iter);
		value = dnode_get(iter);
		dest_header = (struct base_header *) dest;
		dest_header->type = header->type;
		dest_header->len = header->len;
		dest_value = dest + sizeof(struct base_header);
		memcpy(dest_value, value, dest_header->len);
		dest = dest_value + dest_header->len;
		if (iter == dict_last(headers)) break;
		iter = dict_next(headers, iter);
	}

	*out_entry = entry;
	return head_len;
}

struct base_header *
base_entry_get_header(struct base_entry *entry, int type)
{
	char *header_ptr;
	struct base_header *header;
	off_t off = sizeof(struct base_entry);
	while(off < entry->head_len) {
		header_ptr = ((char *) entry) + off;
		header = (struct base_header *) header_ptr;
		if (header->type == type)
			return header;
		off += (sizeof(struct base_header) + header->len);
	}
	return NULL;
}

char *
base_header_get_value(struct base_header *header)
{
	return ((char *) header) + sizeof(struct base_header);
}

int
base_pread_all(int fd, void *buf, size_t count, off_t offset)
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

int
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

