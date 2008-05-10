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
int
base_add_in_header(struct base_peer *, dict_t *headers,
		   uint16_t type, uint16_t len, char *value);
ssize_t
base_peer_marshall_entry_head(struct base_peer *, struct base_entry **,
			      dict_t *headers, size_t content_len);
struct base_header *
base_entry_get_header(struct base_entry *, uint16_t type);
char *
base_header_get_value(struct base_header *);
int
base_pread_all(int, void *, size_t, off_t);
int
base_writev_all(int, struct iovec *, int);
void
base_dir_init(struct base_dir *, struct base_dir *parent, char *comp);
struct base_dir *
base_dir_sub_dir(struct base_dir *, char *);
struct base_extent *
base_dir_child(struct base_dir *, char *);
struct base_path *
base_parse_path_str(struct pool *, char *);
int
base_dir_set_child(struct base_dir *, struct base_entry *,
		   char *comp, size_t comp_len, off_t);
struct base_dir *
base_dir_ensure_sub_dir(struct base_dir *, char *comp, size_t comp_len);

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
	
	while ((c = getopt(argc, argv, "l:a:p")) != -1) {
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
	printf("Sendfile %s\n", BASE_USE_SENDFILE ? "enabled" : "disabled");
}

void
base_peer_init(struct base_peer *peer)
{
	if ((peer->log_fd = open(peer->log_file,
				 O_RDWR | O_CREAT | O_SYNC | O_APPEND,
				 S_IRUSR | S_IWUSR)) == -1)
		err(EXIT_FAILURE, "Cannot open log file");

	base_dir_init(&peer->root, &peer->root, "");
	
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
		off += entry->len;
	}

	peer->log_off = off;

	if (munmap(log, log_len) == -1)
		warn("Cannot unmap log file");
}

void
base_peer_http_callback(struct evhttp_request *req, void *arg)
{
	struct base_peer *peer = (struct base_peer *) arg;
	int res = -1;
	
	switch (req->type) {
	case EVHTTP_REQ_GET:
		res = base_peer_get(peer, req);
	case EVHTTP_REQ_POST:
		res = base_peer_put(peer, req);
	}
	pool_reset(&peer->pool);

	if (res == -1) evhttp_send_error(req, 503, "Error");
}

int
base_peer_get(struct base_peer *peer, struct evhttp_request *req)
{
	char *uri;
	struct base_path *path;
	struct base_dir *dir = &peer->root;

	if (!(uri = evhttp_decode_uri(req->uri))) 
		return -1;

	path = base_parse_path_str(&peer->pool, uri);
	free(uri);
	if (!path) return -1;
	
	for(;;) {
		if (strlen(path->comp) > 0) {
			if (path->next == NULL) {
				// End of path, return entry.
				return base_peer_get_entry(peer, req, dir,
							   path->comp);
			} else {
				// There are further components in
				// path, enter sub-directory and
				// continue.
				dir = base_dir_sub_dir(dir, path->comp);
				path = path->next;
				continue;
			}
		} else {
			// Empty component, return directory listing.
			// (An empty component indicates that the
			// path denotes a directory, e.g. /foo/ is
			// represented as the components "foo" and "".)
			return base_peer_get_dir(peer, req, dir);
		}
	}

	return -1; // not reached, Murphy-willing
}

int
base_peer_get_entry(struct base_peer *peer, 
		    struct evhttp_request *req,
		    struct base_dir *dir,
		    char *name)
{
	struct base_extent *extent;
	if (extent = base_dir_child(dir, name)) {
		if (base_peer_send_content(peer, req, extent) == -1)
			return -1;
		evhttp_send_reply(req, HTTP_OK, "OK", NULL);
		return 0;
	} else {
		evhttp_send_error(req, 404, "Not Found");
		return 0;
	}
}

int
base_peer_get_dir(struct base_peer *peer, 
		  struct evhttp_request *req,
		  struct base_dir *dir)
{
	return -1;
}

struct base_extent *
base_dir_child(struct base_dir *dir, char *name)
{
	dnode_t *dnode = dict_lookup(&dir->children, name);
	if (dnode) return dnode_get(dnode);
	else return NULL;
}

struct base_dir *
base_dir_sub_dir(struct base_dir *dir, char *name)
{
	dnode_t *dnode = dict_lookup(&dir->sub_dirs, name);
	if (dnode) return dnode_get(dnode);
	else return NULL;
}

#if BASE_USE_SENDFILE

int
base_peer_send_content(struct base_peer *peer, 
		       struct evhttp_request *req,
		       struct base_extent *extent)
{
	req->output_buffer->sf_fd = peer->log_fd;
	req->output_buffer->sf_off = extent->off + extent->head_len;
	req->output_buffer->off = extent->len - extent->head_len;
	return 0;
}

#else

int
base_peer_send_content(struct base_peer *peer, 
		       struct evhttp_request *req,
		       struct base_extent *extent)
{
	char *content;
	size_t content_len = extent->len - extent->head_len;
	if (!(content = pool_malloc(&peer->pool, content_len)))
		return -1;
	if (base_pread_all(peer->log_fd, content, content_len,
			   extent->off + extent->head_len) == -1)
		return -1;
	evbuffer_add(req->output_buffer, content, content_len);
	return 0;
}

#endif // BASE_USE_SENDFILE

int
base_header_cmp(struct base_header *h1, struct base_header *h2)
{
	return h1->type - h2->type;
}

/* Construct an entry with various headers and the user-supplied
   content, write it to the log file and add it to the index.  If
   write() fails, we're hosed.  (Yes, this will be improved.) */
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
		return -1;
	
	struct base_entry *entry;
	ssize_t head_len;
	if ((head_len =
	     base_peer_marshall_entry_head(peer, &entry, 
					   &headers, content_len)) == -1)
		return -1;

	struct iovec vec[2] = {
		{ entry, head_len },
		{ content_buf, content_len }
	};
	if (base_writev_all(peer->log_fd, vec, 2) == -1)
		return -1;

	off_t old_log_off = peer->log_off;
	peer->log_off += (head_len + content_len);
	
	if (base_peer_index_entry(peer, entry, old_log_off) == -1)
		return -1;

	evhttp_send_reply(req, HTTP_OK, "OK", NULL);
	return 0;
}

/* Add an entry to the directory index.  This is called when a new
   entry is PUT or DELETEd via the HTTP interface, and when we are
   redoing the log at startup. -- If there's already a document in the
   index with that ID, simply update the index node with the extent of
   the new entry.  Otherwise we have to insert a new index node (and
   maybe directory nodes above), mapping the ID to the extent of the
   new entry.  Or, if the entry is a delete entry, we have to remove
   any existing mapping (and maybe now-empty directory nodes
   above). */
int
base_peer_index_entry(struct base_peer *peer,
		      struct base_entry *entry, 
		      off_t off)
{
	char *id;
	struct base_header *id_header;
	if (!(id_header = base_entry_get_header(entry, BASE_H_ID)))
		return -1;
	id = base_header_get_value(id_header);

	struct base_header *type_header;
	int delete = 0;
	if (type_header = base_entry_get_header(entry, BASE_H_ENTRY_TYPE)) {
		uint8_t *entry_type = base_header_get_value(type_header);
		if (*entry_type == BASE_ENTRY_TYPE_DELETE)
			delete = 1;
	}

	struct base_path *path;
	if (!(path = base_parse_path_str(&peer->pool, id)))
		return -1;

	if (!delete)
		return base_peer_add_index_entry(peer, entry, path, off);
	else
		return base_peer_remove_index_entry(peer, entry, path);

}	

int
base_peer_add_index_entry(struct base_peer *peer, struct base_entry *entry,
			  struct base_path *path, off_t off)
{
	struct base_dir *dir = &peer->root;
	size_t comp_len;
	for(;;) {
		comp_len = strlen(path->comp);
		if (comp_len > 0) {
			if (path->next == NULL) {
				// End of path, create or update child.
				return base_dir_set_child(dir, 
							  entry,
							  path->comp, 
							  comp_len,
							  off);
			} else {
				// There are further path components,
				// ensure that neccessary
				// sub-directory exists and enter it.
				dir = base_dir_ensure_sub_dir(dir, path->comp,
							      comp_len);
				if (!dir) return -1;
				path = path->next;
				continue;
			}
		} else {
			// The path addresses a directory.  This
			// shouldn't really happen.  Todo: Detect this
			// earlier
			return -1;
		}
	}
	return -1; // not reached
}

// Create or update the extent data of an entry in a directory.
int
base_dir_set_child(struct base_dir *dir, struct base_entry *entry,
		   char *comp, size_t comp_len, off_t off)
{
	struct base_extent *extent;
	dnode_t *dnode;
	if (dnode = dict_lookup(&dir->children, comp)) {
		extent = dnode_get(dnode);
		extent->off = off;
		extent->len = entry->len;
		extent->head_len = entry->head_len;
		return 0;
	} else {
		if (dict_isfull(&dir->children)) return -1;
		char *combined_buf, *comp_copy;
		size_t combined_buf_len =
			sizeof(struct base_extent) + comp_len + 1;
		if (!(combined_buf = malloc(combined_buf_len)))
			return -1;
		memset(combined_buf, 0, combined_buf_len);
		extent = (struct base_extent *) combined_buf;
		extent->off = off;
		extent->len = entry->len;
		extent->head_len = entry->head_len;
		comp_copy = combined_buf + sizeof(struct base_extent);
		memcpy(comp_copy, comp, comp_len + 1);
		if (dict_alloc_insert(&dir->children, comp_copy, extent)) {
			return 0;
		} else {
			free(combined_buf);
			return -1;
		}
	}
}

struct base_dir *
base_dir_ensure_sub_dir(struct base_dir *parent, char *comp, size_t comp_len)
{
	struct base_dir *dir;
	if (dir = base_dir_sub_dir(parent, comp)) return dir;
	char *combined_buf, *comp_copy;
	size_t combined_buf_len = 
		sizeof(struct base_dir) + 
		sizeof(dnode_t) +
		comp_len + 1;
	if (!(combined_buf = malloc(combined_buf_len))) return NULL;
	comp_copy = combined_buf + sizeof(struct base_dir) + 
		sizeof(dnode_t);
	memcpy(comp_copy, comp, comp_len + 1);
	dir = (struct base_dir *) combined_buf;
	base_dir_init(dir, parent, comp_copy);
	dnode_t *dnode = (dnode_t *) combined_buf + sizeof(struct base_dir);
	dnode_init(dnode, dir);
	dict_insert(&parent->sub_dirs, dnode, comp_copy);
}

int
base_peer_remove_index_entry(struct base_peer *peer, struct base_entry *entry,
			     struct base_path *path)
{
	struct base_dir *dir = &peer->root;
	for(;;) {
		if (strlen(path->comp) > 0) {
			if (path->next == NULL) {
				// End of path, delete entry and
				// possibly directories above.
				return base_kill_index_entry(dir,
							     path->comp);
			} else {
				// There are further components.  If a
				// corresponding directory exists,
				// enter it, otherwise, we're done.
				// (Can this happen? A delete of a
				// non-existent/non-indexed entry?)
				dir = base_dir_sub_dir(dir, path->comp);
				if (!dir) return 0;
				else continue;
			}
		} else {
			// Path addresses a directory, makes no sense.
			// Detect earlier.
			return -1;
		}
	}
}

int
base_kill_index_entry(struct base_dir *dir, char *comp)
{
	dnode_t *dnode = dict_lookup(&dir->children, comp);
	if (!dnode) return 0; // also delete parents?
	dict_delete(&dir->children, dnode);
	char *buf = dnode_get(dnode);
	free(buf); // gets rid of extent and key
	free(dnode); // todo: put dnode into combined buf, too
	return base_kill_dir_if_empty(dir);
}

int
base_kill_dir_if_empty(struct base_dir *dir)
{
	struct base_dir *parent = dir->parent;
	if (!parent || parent == dir) return 0; // don't delete root
	if ((!dict_count(&dir->children))
	    && (!dict_count(&dir->sub_dirs))) {
		char *comp = dir->comp;
		dnode_t *dnode = dict_lookup(&parent->sub_dirs, 
					     dir->comp);
		if (dnode) {
			dict_delete(&parent->sub_dirs, dnode);
			char *buf = dnode_get(dnode);
			free(buf); // there goes the directory
		} else {
			// something is horribly wrong
		}
		return base_kill_dir_if_empty(parent);
	} else {
		return 0;
	}
}

/* Fill the headers dictionary with headers that should be written to
   disk for the entry corresponding to a HTTP PUT request.  New memory
   for the headers should be allocated from the write pool; it is also
   OK to reference data in the request, as the headers will be written
   before the request is destroyed. */
int
base_peer_populate_in_headers(struct base_peer* peer,
			      struct evhttp_request *req, 
			      dict_t *headers)
{
	// ID header, reference ID from request URL.
	char *id = req->uri;
	size_t id_len = strlen(id);
	uint16_t header_len;
	if (!id) 
		return -1;
	if ((id_len + 1) > BASE_HEADER_LEN_MAX)
		return -1;
	header_len = id_len + 1;
	if (base_add_in_header(peer, headers,
			       BASE_H_ID, header_len, id) == -1)
		return -1;

	// If the method is DELETE set the entry type to delete.
	const char *override;
	if ((override = evhttp_find_header(req->input_headers,
					   BASE_HTTP_OVERRIDE))
	    && (strcasecmp(override, BASE_HTTP_DELETE) == 0)) {
		if (base_add_in_header(peer, headers,
				       BASE_H_ENTRY_TYPE, 1,
				       (char *) &BASE_ENTRY_TYPE_DELETE) == -1)
			return -1;
	}
	
	return 0;
}

/* Add a header to an incoming entry.  Memory (e.g. for the value)
   should be allocated by the caller from the write pool or point to
   request data. */
int
base_add_in_header(struct base_peer *peer, dict_t *headers, 
		   uint16_t type, uint16_t len, char *value)
{
	struct base_header *header;
	dnode_t *dnode;
	if (type > BASE_HEADER_TYPE_MAX)
		return -1;
	if (len > BASE_HEADER_LEN_MAX)
		return -1;
	if (!(dnode = pool_malloc(&peer->pool, sizeof(dnode_t))))
		return -1;
	if (!(header = pool_malloc(&peer->pool, sizeof(struct base_header))))
		return -1;
	header->type = type;
	header->len = len;
	dnode_init(dnode, value);
	dict_insert(headers, dnode, header);
	return 0;
}

/* Create the binary representation of the head of an entry so that
   the content can be written after it.  The memory is allocated from
   the write pool. */
ssize_t
base_peer_marshall_entry_head(struct base_peer *peer, 
			      struct base_entry **out_entry,
			      dict_t *headers, 
			      size_t content_len)
{
	// Get the total length of the head, including all headers.
	// Todo: There is the unlikely possibility of an overflow of
	// the head_len if there are very many headers.
	size_t head_len = sizeof(struct base_entry);
	const struct base_header *header;
	dnode_t *iter = dict_first(headers);
	while(iter) {
		header = dnode_getkey(iter);
		head_len += (sizeof(struct base_header) + header->len);
		if (iter == dict_last(headers)) break;
		iter = dict_next(headers, iter);
	}
	if (head_len > BASE_ENTRY_HEAD_LEN_MAX)	return -1;
	
	struct base_entry *entry;
	if (!(entry = pool_malloc(&peer->pool, head_len)))
		return -1;
	entry->head_len = head_len;
	entry->len = head_len + content_len;
	
	// Serialize the headers by looping through the supplied
	// dictionary and writing them into their destination
	// locations in the space allocated in the entry's head.
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
base_entry_get_header(struct base_entry *entry, uint16_t type)
{
	char *header_ptr;
	struct base_header *header;
	off_t off = sizeof(struct base_entry);
	if (type > BASE_HEADER_TYPE_MAX) return NULL;
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

/* Adapted from Linux Journal, September 2007. */
int
base_writev_all(int fd, struct iovec *vec, int count)
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

void
base_dir_init(struct base_dir *dir, struct base_dir *parent)
{
	dict_init(&dir->children, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) strcmp);
	dict_init(&dir->sub_dirs, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) strcmp);
	dir->parent = parent;
}

/* "/"         -> [""]
   "/foo"      -> ["foo"]
   "/foo/"     -> ["foo", ""]
   "/foo/bar"  -> ["foo", "bar"] 
   "/foo/bar/" -> ["foo", "bar", ""] */
struct base_path *
base_parse_path_str(struct pool *pool, char *str)
{
	struct base_path *first = NULL, *path = NULL, *prev = NULL;
	size_t len = strlen(str), i = 0, comp_len;
	char *comp, *end;
	while(i < len) {
		prev = path;
		if (!(path = pool_calloc(pool, sizeof(struct base_path))))
			return NULL;
		if (!first) first = path;
		if (prev) prev->next = path;
		i++;
		comp = str + i;
		end = strchr(comp, '/');
		if (!end) 
			comp_len = len - i;
		else 
			comp_len = end - comp;
		path->comp = pool_strndup(pool, comp, comp_len);
		i += comp_len;
	}
	return first;
}
