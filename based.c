#include "based.h"

/* Initialization */
void
base_peer_usage();
void
base_peer_configure(struct base_peer *, int argc, char **argv);
void
base_peer_init(struct base_peer *);
void
base_peer_redo_log(struct base_peer *);

/* HTTP handling */
void
base_peer_http_callback(struct evhttp_request *, void *peer);

/* Egress data path */
int
base_peer_get(struct base_peer *, struct evhttp_request *);
int
base_peer_get_entry(struct base_peer *peer, 
		    struct evhttp_request *req,
		    struct base_dir *dir,
		    char *name);
int
base_peer_send_content(struct base_peer *peer,
		       struct evhttp_request *req,
		       struct base_extent *extent);
int
base_peer_get_dir(struct base_peer *peer, 
		  struct evhttp_request *req,
		  struct base_dir *dir,
		  int level);

/* Ingress data path */
int
base_peer_put(struct base_peer *, struct evhttp_request *);
int
base_peer_populate_in_headers(struct base_peer*, struct evhttp_request *, 
			      dict_t *headers);
int
base_add_in_header(struct base_peer *, dict_t *headers,
		   uint16_t type, uint16_t len, char *value);
ssize_t
base_peer_marshall_entry_head(struct base_peer *, struct base_entry **,
			      dict_t *headers, size_t content_len);

/* Index maintenance */
int
base_peer_index_entry(struct base_peer *, struct base_entry *, off_t);
int
base_peer_add_index_entry(struct base_peer *peer, struct base_entry *entry,
			  struct base_path *path, off_t off);
int
base_peer_remove_index_entry(struct base_peer *peer, struct base_path *path);
int
base_dir_set_child(struct base_dir *, struct base_entry *,
		   char *name, size_t name_len, off_t);
struct base_dir *
base_dir_ensure_sub_dir(struct base_dir *, char *name, size_t name_len);
int
base_kill_index_entry(struct base_dir *dir, char *name);
int
base_kill_dir_if_empty(struct base_dir *dir);

/* Utilities */
struct base_header *
base_entry_get_header(struct base_entry *, uint16_t type);
char *
base_header_get_value(struct base_header *);
struct base_path *
base_parse_path_str(struct pool *, char *);
void
base_dir_init(struct base_dir *, struct base_dir *parent, char *name);
struct base_extent *
base_dir_child(struct base_dir *, char *name);
struct base_dir *
base_dir_sub_dir(struct base_dir *, char *name);
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

	printf("Redoing log...\n");
	base_peer_redo_log(&peer);
	printf("Redoing log... done\n");

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
	int i = 0;
	while(off < log_len) {
		i++;
		entry_ptr = log + off;
		entry = (struct base_entry *) entry_ptr;
		if (base_peer_index_entry(peer, entry, off) == -1) {
			fprintf(stderr, "Cannot index entry %d (error %d)\n",
				i, base_errno);
		}
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
		break;
	case EVHTTP_REQ_PUT:
	case EVHTTP_REQ_POST:
	case EVHTTP_REQ_DELETE:
		res = base_peer_put(peer, req);
		break;
	}
	pool_reset(&peer->pool);

	if (res == -1) evhttp_send_error(req, 503, "error");
}

/* Reading and sending outgoing entries or directories */

int
base_peer_get(struct base_peer *peer, struct evhttp_request *req)
{
	char *uri, *query, *uri_path, *level_str;
	int level = 0;
	struct base_path *path;
	struct base_dir *dir = &peer->root;

	if (!(uri = evhttp_decode_uri(req->uri))) {
		base_errno = BASE_EURL;
		return -1;
	}

	/* If the URI has query arguments, look for the level argument
	   (for deep directory listings) and remove the query from the
	   parsed path.  Todo: search '?' before decoding URI? */
	if (query = strchr(uri, '?')) {
		if (!(uri_path = pool_strndup(&peer->pool, uri, query - uri))) {
			free(uri);
			base_errno = BASE_ENOMEM;
			return -1;
		}
		struct evkeyvalq q;
		evhttp_parse_query(query, &q);
		if (level_str = (char *) evhttp_find_header(&q, "level")) {
			level = atoi(level_str);
		}
		evhttp_clear_headers(&q);
	} else {
		uri_path = uri;
	}

	path = base_parse_path_str(&peer->pool, uri_path);
	free(uri);
	if (!path) return -1;
	
	for(;;) {
		if (strlen(path->name) > 0) {
			if (path->next == NULL) {
				// End of path, return entry.
				return base_peer_get_entry(peer, req, dir,
							   path->name);
			} else {
				// There are further components in
				// path, try to enter sub-directory
				// and continue.
				if (!(dir = base_dir_sub_dir(dir, path->name))) {
					evhttp_send_error(req, 404, "not found");
					return 0;
				}
				path = path->next;
				continue;
			}
		} else {
			// Empty component, return directory listing.
			// (An empty component indicates that the
			// path denotes a directory, e.g. /foo/ is
			// represented as the components "foo" and "".)
			return base_peer_get_dir(peer, req, dir, level);
		}
	}

	assert(0); // not reached
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
	if (!(content = pool_malloc(&peer->pool, content_len))) {
		base_errno = BASE_ENOMEM;
		return -1;
	}
	if (base_pread_all(peer->log_fd, content, content_len,
			   extent->off + extent->head_len) == -1) {
		base_errno = BASE_EIO;
		return -1;
	}
	evbuffer_add(req->output_buffer, content, content_len);
	return 0;
}

#endif // BASE_USE_SENDFILE

/* Directory listing */

struct base_dir_lister {
	struct base_peer *peer;
	struct evhttp_request *req;
	int level, total_level;
};

void
base_dir_listing_sub_dir(dict_t *ign, dnode_t *dnode, void *arg)
{
	struct base_dir_lister *lister = arg;
	int i;
	for (i = lister->level; i < lister->total_level; i++) {
		evbuffer_add_printf(lister->req->output_buffer, "\t");
	}
	evbuffer_add_printf(lister->req->output_buffer, "%s/\n", dnode_getkey(dnode));
	if (lister->level > 0) {
		struct base_dir *sub_dir = dnode_get(dnode);
		base_peer_list_dir(lister->peer, lister->req, sub_dir,
				   lister->level - 1, lister->total_level);
	}
}

void
base_dir_listing_child(dict_t *ign, dnode_t *dnode, void *arg)
{
	struct base_dir_lister *lister = arg;
	int i;
	for (i = lister->level; i < lister->total_level; i++) {
		evbuffer_add_printf(lister->req->output_buffer, "\t");
	}
	evbuffer_add_printf(lister->req->output_buffer, "%s\n", dnode_getkey(dnode));
}

int
base_peer_list_dir(struct base_peer *peer,
		   struct evhttp_request *req,
		   struct base_dir *dir,
		   int level,
		   int total_level)
{
	struct base_dir_lister lister;
	memset(&lister, 0, sizeof lister);
	lister.peer = peer;
	lister.req = req;
	lister.level = level;
	lister.total_level = total_level;
	dict_process(&dir->sub_dirs, &lister, base_dir_listing_sub_dir);
	dict_process(&dir->children, &lister, base_dir_listing_child);
}

int
base_peer_get_dir(struct base_peer *peer,
		  struct evhttp_request *req,
		  struct base_dir *dir,
		  int level)
{
	base_peer_list_dir(peer, req, dir, level, level);
	evhttp_add_header(req->output_headers, "Content-type", 
			  "text/plain; charset=utf-8");
	evhttp_send_reply(req, HTTP_OK, "OK", NULL);
	return 0;
}

/* Writing and indexing incoming entries */

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
	if (content_len > BASE_ENTRY_CONTENT_LEN_MAX) {
		base_errno = BASE_EREQ;
		return -1;
	}
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

	if (base_write_all(peer->log_fd, entry, head_len) == -1) {
		base_errno = BASE_EIO;
		return -1;
	}
	if (base_write_all(peer->log_fd, content_buf, content_len) == -1) {
		base_errno = BASE_EIO;
		return -1;
	}

	off_t old_log_off = peer->log_off;
	peer->log_off += (head_len + content_len);
	
	if (base_peer_index_entry(peer, entry, old_log_off) == -1)
		return -1;

	evhttp_send_reply(req, HTTP_OK, "OK", NULL);
	return 0;
}

/* Index an entry.  This is called when a new entry is PUT or DELETEd
   via the HTTP interface, and when we are redoing the log at
   startup. -- If there's already a document in the index with that
   ID, simply update the index node with the extent of the new entry.
   Otherwise we have to insert a new index node (and maybe directory
   nodes above), mapping the ID to the extent of the new entry.  Or,
   if the entry is a delete entry, we have to remove any existing
   mapping (and maybe now-empty directory nodes above). */
int
base_peer_index_entry(struct base_peer *peer,
		      struct base_entry *entry, 
		      off_t off)
{
	char *id;
	struct base_header *id_header;
	if (!(id_header = base_entry_get_header(entry, BASE_H_ID))) {
		errno = BASE_EENTRY;
		return -1;
	}
	id = base_header_get_value(id_header);

	struct base_header *type_header;
	int delete = 0;
	if (type_header = base_entry_get_header(entry, BASE_H_ENTRY_TYPE)) {
		uint8_t *entry_type = base_header_get_value(type_header);
		if (*entry_type == BASE_ENTRY_TYPE_DELETE)
			delete = 1;
	}

	struct base_path *path;
	if (!(path = base_parse_path_str(&peer->pool, id))) {
		base_errno = BASE_EPATH;
		return -1;
	}

	if (!delete)
		return base_peer_add_index_entry(peer, entry, path, off);
	else
		return base_peer_remove_index_entry(peer, path);
}

int
base_peer_add_index_entry(struct base_peer *peer, struct base_entry *entry,
			  struct base_path *path, off_t off)
{
	struct base_dir *dir = &peer->root;
	size_t name_len;
	for(;;) {
		name_len = strlen(path->name);
		if (name_len > 0) {
			if (path->next == NULL) {
				// End of path, create or update child.
				return base_dir_set_child(dir, 
							  entry,
							  path->name, 
							  name_len,
							  off);
			} else {
				// There are further path components
				// -- ensure that the neccessary
				// sub-directory exists and enter it.
				if (!(dir = base_dir_ensure_sub_dir(dir, 
								    path->name,
								    name_len))) {
					base_errno = BASE_EPATH;
					return -1;
				}
				path = path->next;
				continue;
			}
		} else {
			// The path addresses a directory.  This
			// shouldn't really happen.  Todo: Detect this
			// earlier.
			base_errno = BASE_EPATH;
			return -1;
		}
	}

	base_errno = BASE_EBUG;
	return -1; // not reached
}

/* Create or update the extent data of an entry in a directory. */
int
base_dir_set_child(struct base_dir *dir, struct base_entry *entry,
		   char *name, size_t name_len, off_t off)
{
	struct base_extent *extent;
	dnode_t *dnode;
	if (dnode = dict_lookup(&dir->children, name)) {
		extent = dnode_get(dnode);
		extent->off = off;
		extent->len = entry->len;
		extent->head_len = entry->head_len;
		return 0;
	} else {
		if (dict_isfull(&dir->children)) return -1;
		char *combined_buf, *name_copy;
		size_t combined_buf_len =
			sizeof(struct base_extent) + name_len + 1;
		if (!(combined_buf = malloc(combined_buf_len))) {
			base_errno = BASE_ENOMEM;
			return -1;
		}
		memset(combined_buf, 0, combined_buf_len);
		extent = (struct base_extent *) combined_buf;
		extent->off = off;
		extent->len = entry->len;
		extent->head_len = entry->head_len;
		name_copy = combined_buf + sizeof(struct base_extent);
		memcpy(name_copy, name, name_len);
		if (dict_alloc_insert(&dir->children, name_copy, extent)) {
			return 0;
		} else {
			free(combined_buf);
			base_errno = BASE_ENOMEM;
			return -1;
		}
	}
}

struct base_dir *
base_dir_ensure_sub_dir(struct base_dir *parent, char *name, size_t name_len)
{
	struct base_dir *dir;
	if (dir = base_dir_sub_dir(parent, name)) return dir;
	char *combined_buf, *name_copy;
	size_t combined_buf_len = sizeof(struct base_dir) + name_len + 1;
	if (!(combined_buf = malloc(combined_buf_len))) return NULL;
	memset(combined_buf, 0, combined_buf_len);
	name_copy = combined_buf + sizeof(struct base_dir);
	memcpy(name_copy, name, name_len);
	dir = (struct base_dir *) combined_buf;
	base_dir_init(dir, parent, name_copy);
	dnode_t *dnode = malloc(sizeof(dnode_t));
	if (!dnode) {
		free(combined_buf);
		return NULL;
	}
	dnode_init(dnode, dir);
	dict_insert(&parent->sub_dirs, dnode, name_copy);
	return dir;
}

int
base_peer_remove_index_entry(struct base_peer *peer, struct base_path *path)
{
	struct base_dir *dir = &peer->root;
	for(;;) {
		if (strlen(path->name) > 0) {
			if (path->next == NULL) {
				// End of path, delete entry and
				// possibly directories above.
				return base_kill_index_entry(dir,
							     path->name);
			} else {
				// There are further components.  If a
				// corresponding directory exists,
				// enter it, otherwise, we're done.
				if (!(dir = base_dir_sub_dir(dir, path->name)))
					return 0;
				path = path->next;
				continue;
			}
		} else {
			// Path addresses a directory, makes no sense.
			// Todo: Detect earlier.
			base_errno = BASE_EPATH;
			return -1;
		}
	}

	return 0;
}

int
base_kill_index_entry(struct base_dir *dir, char *name)
{
	dnode_t *dnode = dict_lookup(&dir->children, name);
	if (dnode) {
		dict_delete(&dir->children, dnode);
		char *combined_buf = dnode_get(dnode);
		free(combined_buf);
		free(dnode);
	}
	return base_kill_dir_if_empty(dir);
}

int
base_kill_dir_if_empty(struct base_dir *dir)
{
	struct base_dir *parent = dir->parent;
	if (parent == dir) return 0; // don't delete root
	if ((!dict_count(&dir->children)) && (!dict_count(&dir->sub_dirs))) {
		char *name = dir->name;
		dnode_t *dnode = dict_lookup(&parent->sub_dirs, dir->name);
		if (dnode) {
			dict_delete(&parent->sub_dirs, dnode);
			char *combined_buf = dnode_get(dnode);
			free(combined_buf);
			free(dnode);
		} else {
			// something is horribly wrong
		}
		return base_kill_dir_if_empty(parent);
	} else {
		return 0;
	}
}

/* Fill the headers dictionary with headers that should be written to
   disk for the entry corresponding to a HTTP PUT or DELETE request.
   New memory for the headers should be allocated from the write pool;
   it is also OK to reference data in the request, as the headers will
   be written before the request is destroyed. */
int
base_peer_populate_in_headers(struct base_peer* peer,
			      struct evhttp_request *req, 
			      dict_t *headers)
{
	// ID header
	char *id, *id_copy;
	size_t id_len;
	uint16_t header_len;
	// Enh: this URI decoding is done two times per request
	if (!(id = evhttp_decode_uri(req->uri))) {
		base_errno = BASE_EURL;
		return -1;
	}
	id_len = strlen(id);
	header_len = id_len + 1;
	if (header_len > BASE_HEADER_LEN_MAX) {
		base_errno = BASE_EID;
		goto err;
	}
	if (!(id_copy = pool_strndup(&peer->pool, id, id_len))) {
		base_errno = BASE_ENOMEM;
		goto err;
	}
	if (base_add_in_header(peer, headers,
			       BASE_H_ID, header_len, id_copy) == -1) {
		base_errno = BASE_EHEADER;
		goto err;
	}
	// Entry type header for deletions
	if (base_req_is_delete(req)) {
		if (base_add_in_header(peer, headers, BASE_H_ENTRY_TYPE, 1,
				       (char *) &BASE_ENTRY_TYPE_DELETE) == -1) {
			base_errno = BASE_EHEADER;
			goto err;
		}
	}
	free(id);
	return 0;
 err:
	free(id);
	return -1;
}

int
base_req_is_delete(struct evhttp_request *req)
{
	const char *override;
	if (req->type == EVHTTP_REQ_DELETE) 
		return 1;
	if (override = evhttp_find_header(req->input_headers, BASE_HTTP_OVERRIDE))
		return strcasecmp(override, BASE_HTTP_DELETE) == 0;
	else
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
	if ((type > BASE_HEADER_TYPE_MAX) || (len > BASE_HEADER_LEN_MAX)) {
		base_errno = BASE_EHEADER;
		return -1;
	}
	if (!(dnode = pool_malloc(&peer->pool, sizeof(dnode_t)))) {
		base_errno = BASE_ENOMEM;
		return -1;
	}
	if (!(header = pool_malloc(&peer->pool, sizeof(struct base_header)))) {
		base_errno = BASE_ENOMEM;
		return -1;
	}
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
	if (head_len > BASE_ENTRY_HEAD_LEN_MAX)	{
		base_errno = BASE_EHEAD;
		return -1;
	}
	
	struct base_entry *entry;
	if (!(entry = pool_malloc(&peer->pool, head_len))) {
		base_errno = BASE_ENOMEM;
		return -1;
	}
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

/* Utilities */

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

/* Parses a hierarchical path into a series of components.  HTTP URL
   stuff like query args should have already been removed from the
   string.

   "/"         -> [""]
   "/foo"      -> ["foo"]
   "/foo/"     -> ["foo", ""]
   "/foo/bar"  -> ["foo", "bar"] 
   "/foo/bar/" -> ["foo", "bar", ""] */
struct base_path *
base_parse_path_str(struct pool *pool, char *str)
{
	struct base_path *first = NULL, *path = NULL, *prev = NULL;
	size_t len = strlen(str), i = 0, name_len;
	char *name, *end;
	while(i < len) {
		prev = path;
		if (!(path = pool_calloc(pool, sizeof(struct base_path))))
			return NULL;
		if (!first) first = path;
		if (prev) prev->next = path;
		i++;
		name = str + i;
		end = strchr(name, '/');
		if (!end) 
			name_len = len - i;
		else 
			name_len = end - name;
		path->name = pool_strndup(pool, name, name_len);
		i += name_len;
	}
	return first;
}

void
base_dir_init(struct base_dir *dir, struct base_dir *parent, char *name)
{
	dict_init(&dir->children, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) strcmp);
	dict_init(&dir->sub_dirs, DICTCOUNT_T_MAX,
		  (int (*)(const void *, const void *)) strcmp);
	dir->parent = parent;
	dir->name = name;
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
	while(written < count) {
		if ((res = write(fd, buf + written, count - written)) == -1)
			return -1;
		else
			written += res;
	}
	return 0;
}
