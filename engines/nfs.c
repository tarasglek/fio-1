// https://github.com/axboe/fio/pull/762 sample pull req for new engine
#include <poll.h>

#if 0
#define DEBUG_PRINT(...) \
	fprintf(stderr, __VA_ARGS__)

#else
#define DEBUG_PRINT(...)
#endif

#define FAIL(...) { \
	log_err(__VA_ARGS__); \
	return 1; \
}

#include <stdlib.h>
#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw.h>
#include <nfsc/libnfs-raw-mount.h>

// workaround for conflict with fio headers
#include "../fio.h"
#include "../optgroup.h"

struct rpc_context *mount_context;

enum nfs_op_type {
	NFS_READ_WRITE = 0,
	NFS_STAT_MKDIR_RMDIR,
	NFS_STAT_TOUCH_RM,
};

/*
 * The io engine can define its own options within the io engine source.
 * The option member must not be at offset 0, due to the way fio parses
 * the given option. Just add a padding pointer unless the io engine has
 * something usable.
 */
struct fio_skeleton_options {
	struct nfs_context *context;
	char *nfs_url;
	char *nfs_read;
	char *nfs_write;
	char *nfs_trim;
	enum nfs_op_type op_type;
	int (*read)(struct fio_skeleton_options *o, struct io_u *io_u);
	int (*write)(struct fio_skeleton_options *o, struct io_u *io_u);
	int (*trim)(struct fio_skeleton_options *o, struct io_u *io_u);
	int outstanding_events; // IOs issued to libnfs, that have not returned yet
	int prev_requested_event_index; // event last returned via fio_skeleton_event
	int next_buffered_event; // round robin-pointer within events[]
	int buffered_event_count; // IOs completed by libnfs faiting for FIO
	int free_event_buffer_index; // next empty buffer
	unsigned int queue_depth; // nfs_callback needs this info, but doesn't have fio td structure to pull it from
	struct io_u**events;
};

struct nfs_data {
	struct nfsfh *nfsfh;
	struct fio_skeleton_options *options;
};

static struct fio_option options[] = {
	{
		.name     = "nfs_url",
		.lname    = "nfs_url",
		.type     = FIO_OPT_STR_STORE,
		.help	= "libnfs url, of format nfs://<server|ipv4|ipv6>/path[?arg=val[&arg=val]*]",
		.off1     = offsetof(struct fio_skeleton_options, nfs_url),
		.category = FIO_OPT_C_ENGINE,
		.group	= __FIO_OPT_G_NFS,
	},
	{
		.name     = "nfs_write",
		.lname    = "nfs_write",
		.type     = FIO_OPT_STR_STORE,
		.help	= "one of write,mkdir,touch",
		.off1     = offsetof(struct fio_skeleton_options, nfs_write),
		.def	  = "write",
		.category = FIO_OPT_C_ENGINE,
		.group	= __FIO_OPT_G_NFS,
	},
	{
		.name     = "nfs_read",
		.lname    = "nfs_read",
		.type     = FIO_OPT_STR_STORE,
		.help	= "one of read, readdir, stat",
		.off1     = offsetof(struct fio_skeleton_options, nfs_read),
		.def	  = "read",
		.category = FIO_OPT_C_ENGINE,
		.group	= __FIO_OPT_G_NFS,
	},
	{
		.name     = "nfs_trim",
		.lname    = "nfs_trim",
		.type     = FIO_OPT_STR_STORE,
		.help	= "One of rmdir, rm",
		.off1     = offsetof(struct fio_skeleton_options, nfs_trim),
		.def	  = "rmdir",
		.category = FIO_OPT_C_ENGINE,
		.group	= __FIO_OPT_G_NFS,
	},
	{
		.name     = NULL,
	},
};


static void nfs_callback(int res, struct nfs_context *nfs, void *data,
                       void *private_data);


/*
 * The ->event() hook is called to match an event number with an io_u.
 * After the core has called ->getevents() and it has returned eg 3,
 * the ->event() hook must return the 3 events that have completed for
 * subsequent calls to ->event() with [0-2]. Required.
 */
static struct io_u *fio_skeleton_event(struct thread_data *td, int event)
{
	struct fio_skeleton_options *o = td->eo;
	struct io_u *io_u = o->events[o->next_buffered_event];
	DEBUG_PRINT("fio_skeleton_event %d\n", event);
	assert(o->events[o->next_buffered_event]);
	o->events[o->next_buffered_event] = NULL;
	o->next_buffered_event = (o->next_buffered_event + 1) % td->o.iodepth;
	// validate our state machine
	assert(o->buffered_event_count);
	o->buffered_event_count--;
	assert(io_u);
	// we need to assert that fio_skeleton_event is being called in sequential fashion
	DEBUG_PRINT("before o->prev_requested_event_index:%d event:%d\n", o->prev_requested_event_index, event);
	assert(event == 0 || o->prev_requested_event_index + 1 == event);
	if (o->buffered_event_count == 0) {
		o->prev_requested_event_index = -1;
	} else {
		o->prev_requested_event_index = event;
	}
	DEBUG_PRINT("after o->prev_requested_event_index:%d event:%d\n", o->prev_requested_event_index, event);

	return io_u;
}

static int nfs_event_loop(struct thread_data *td, bool flush) {
	struct fio_skeleton_options *o = td->eo;
	struct pollfd pfds[1]; /* nfs:0 */
	DEBUG_PRINT("+nfs_event_loop o->buffered_event_count:%d\n", o->buffered_event_count);
	// we already have stuff queued for fio, no need to waste cpu on poll()
	if (o->buffered_event_count) {
		DEBUG_PRINT("why bother me?\n");
		return o->buffered_event_count;
	}


#define SHOULD_WAIT() (o->outstanding_events == td->o.iodepth || (flush && o->outstanding_events))

	do {
		//td->o.timeout is in microseconds, but poll uses miliseconds
		int timeout = SHOULD_WAIT() ? (td->o.timeout / 1000) : 0;
		int ret = 0;
		pfds[0].fd = nfs_get_fd(o->context);
		pfds[0].events = nfs_which_events(o->context);
		ret = poll(&pfds[0], 1, timeout);
		DEBUG_PRINT("poll(timeout=%d)=%d full=%d outstanding=%d flush=%d\n",
			timeout, ret, o->outstanding_events == td->o.iodepth,  o->outstanding_events, flush);
		if (ret < 0) {
			FAIL("Poll failed");
		}

		if (nfs_service(o->context, pfds[0].revents) < 0) {
			FAIL("nfs_service failed\n");
		}

		if (timeout != 0 && ret == 0){
			log_err("Error: Timed out waiting for io events\n");
			log_err("poll(timeout=%d)=%d full=%d outstanding=%d flush=%d\n",
				timeout, ret, o->outstanding_events == td->o.iodepth,  o->outstanding_events, flush);
			log_err("fd: %d\n", pfds[0].fd);
			log_err("printing file information:\n");
			char err_cmd[100];
			sprintf(err_cmd, "lsof -a -i -p %d", getpid());
			system(err_cmd);

			// Call nfs_callback to record an error from each outstanding connection
			// -62 is ETIME, timer expired which is the most relevant for this failure
			nfs_callback(-62, o->context, NULL, (void*) o->events[o->next_buffered_event]);
			return 1;
		}
	} while (SHOULD_WAIT());
	DEBUG_PRINT("-nfs_event_loop %d\n", o->buffered_event_count);
	// my_backtrace();
	return o->buffered_event_count;
}
#undef SHOULD_WAIT
/*
 * The ->getevents() hook is used to reap completion events from an async
 * io engine. It returns the number of completed events since the last call,
 * which may then be retrieved by calling the ->event() hook with the event
 * numbers. Required.
 */
static int fio_skeleton_getevents(struct thread_data *td, unsigned int min,
				  unsigned int max, const struct timespec *t)
{
	return nfs_event_loop(td, false);
}

/*
 * The ->cancel() hook attempts to cancel the io_u. Only relevant for
 * async io engines, and need not be supported.
 */
static int fio_skeleton_cancel(struct thread_data *td, struct io_u *io_u)
{
	DEBUG_PRINT("fio_skeleton_cancel\n");

	return 0;
}

static void nfs_callback(int res, struct nfs_context *nfs, void *data,
                       void *private_data)
{
	struct io_u *io_u = private_data;
	struct nfs_data *nfs_data = io_u->file->engine_data;
	struct fio_skeleton_options *o = nfs_data->options;
	DEBUG_PRINT("nfs_cb@%llu=%d io_u=%p\n", io_u->offset, res, io_u);
	if (res == -2 /*NFS3ERR_NOENT*/ && io_u->ddir == DDIR_TRIM) {
		DEBUG_PRINT("Ignorning: %s\n", nfs_get_error(o->context));
		res = 0;
	}
	if (res < 0) {
		log_err("Failed NFS operation(code:%d): %s\n", res, nfs_get_error(o->context));
		io_u->error = -res;
		// res is used for read math below, don't wanna mass negative there
		res = 0;
	} else if (io_u->ddir == DDIR_READ && o->op_type == NFS_READ_WRITE) {
		memcpy(io_u->buf, data, res);
		if (res == 0) {
			log_err("Got NFS EOF, this is probably not expected\n");
		}
	}
	// I guess fio uses resid to track remaining data
	io_u->resid =  o->op_type == NFS_READ_WRITE ? (io_u->xfer_buflen - res) : 0;

	assert(!o->events[o->free_event_buffer_index]);
	o->events[o->free_event_buffer_index] = io_u;
	o->free_event_buffer_index = (o->free_event_buffer_index + 1) % o->queue_depth;
	o->outstanding_events--;
	o->buffered_event_count++;
}

static int queue_write(struct fio_skeleton_options *o, struct io_u *io_u) {
	struct nfs_data *nfs_data = io_u->engine_data;
	return nfs_pwrite_async(o->context, nfs_data->nfsfh,
                           io_u->offset, io_u->buflen, io_u->buf, nfs_callback,
                           io_u);
}

static int queue_read(struct fio_skeleton_options *o, struct io_u *io_u) {
	struct nfs_data *nfs_data = io_u->engine_data;
	return nfs_pread_async(o->context,  nfs_data->nfsfh, io_u->offset, io_u->buflen, nfs_callback,  io_u);
}

// todo: reverse numbers to improve name distribution
#define NFS_FILENAME(io_u, buf) \
	char buf[256]; \
	sprintf(buf, "%s/%llx", io_u->file->file_name, io_u->offset);

static int queue_stat(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_stat64_async(o->context, buf, nfs_callback, io_u);
}

static int queue_mkdir(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_mkdir_async(o->context, buf, nfs_callback, io_u);
}

static int queue_rmdir(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_rmdir_async(o->context, buf, nfs_callback, io_u);
}

/** libnfs async versions of creat/open are useless, they don't let you pass own callback data
 * so for now touch is sync
 */
static int sync_touch(struct fio_skeleton_options *o, struct io_u *io_u) {
	struct nfsfh *nfsfh = NULL;
	int ret = 0;
	NFS_FILENAME(io_u, buf)
	ret = nfs_creat(o->context, buf, 0, &nfsfh);
	if (ret < 0) {
		FAIL("Failed to create file '%s': %s\n", buf, nfs_get_error(o->context));
	}
	ret = nfs_close(o->context, nfsfh);
	if (ret < 0) {
		FAIL("Failed to close file '%s': %s\n", buf, nfs_get_error(o->context));
	}
	return 0;
}

static int queue_rm(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_unlink_async(o->context, buf, nfs_callback, io_u);
}

#undef NFS_FILENAME
/*
 * The ->queue() hook is responsible for initiating io on the io_u
 * being passed in. If the io engine is a synchronous one, io may complete
 * before ->queue() returns. Required.
 *
 * The io engine must transfer in the direction noted by io_u->ddir
 * to the buffer pointed to by io_u->xfer_buf for as many bytes as
 * io_u->xfer_buflen. Residual data count may be set in io_u->resid
 * for a short read/write.
 */
static enum fio_q_status fio_skeleton_queue(struct thread_data *td,
					    struct io_u *io_u)
{
	struct nfs_data *nfs_data = io_u->file->engine_data;
	struct fio_skeleton_options *o = nfs_data->options;
	struct nfs_context *nfs = o->context;
	int err;
	enum fio_q_status ret = FIO_Q_QUEUED;
	DEBUG_PRINT("fio_skeleton_queue %s @%llu size:%llu\n",
		(io_u->ddir == DDIR_READ ? "read" : "write"),
		io_u->offset, io_u->buflen);

	io_u->engine_data = nfs_data;
	switch(io_u->ddir) {
		case DDIR_WRITE:
			err = o->write(o, io_u);
			// hack, proper fix is to add fio_q_status to every callback so they could specify if sync/async behavior
			if (o->op_type == NFS_STAT_TOUCH_RM)
				ret = FIO_Q_COMPLETED;
			break;
		case DDIR_READ:
			err = o->read(o, io_u);
			break;
		case DDIR_TRIM:
			err = o->trim(o, io_u);
			break;
		default:
			FAIL("fio_skeleton_queue unhandled io %d\n", io_u->ddir);
	}
	if (err) {
		FAIL("Failed to queue nfs op: %s\n", nfs_get_error(nfs));
		td->error = 1;
		return FIO_Q_COMPLETED;
	}
	o->outstanding_events++;
	return ret;
}

/*
 * The ->prep() function is called for each io_u prior to being submitted
 * with ->queue(). This hook allows the io engine to perform any
 * preparatory actions on the io_u, before being submitted. Not required.
 */
// static int fio_skeleton_prep(struct thread_data *td, struct io_u *io_u)
// {
// 	DEBUG_PRINT("fio_skeleton_prep\n");
// 	return 0;
// }

/** Do a mount if one has not been done before */
static int do_mount(struct thread_data *td, const char *url)
{
	size_t event_size = sizeof(struct io_u **) * td->o.iodepth;
	struct fio_skeleton_options *options = td->eo;
	struct nfs_url *nfs_url = NULL;
	int ret = 0;
	int path_len = 0;
	char *mnt_dir = NULL;

	if (options->context) {
		return 0;
	}

	options->context = nfs_init_context();
	if (options->context == NULL) {
		FAIL("failed to init nfs context\n");
	}

	options->events = malloc(event_size);
	memset(options->events, 0, event_size);

	options->prev_requested_event_index = -1;
	options->queue_depth = td->o.iodepth;

	char myurl[PATH_MAX];
	nfs_url = nfs_parse_url_full(options->context, make_filename(myurl, PATH_MAX, url, "some_nfs_job", td->subjob_number, 0));
	path_len = strlen(nfs_url->path);
	mnt_dir = malloc(path_len + strlen(nfs_url->file) + 1);
	strcpy(mnt_dir, nfs_url->path);
	strcpy(mnt_dir + strlen(nfs_url->path), nfs_url->file);
	DEBUG_PRINT("nfs_mount(%s, %s)\n", nfs_url->server, mnt_dir);
	ret = nfs_mount(options->context, nfs_url->server, mnt_dir);
	if (ret != 0) {
		log_err("Failed to nfs mount %s with code %d: %s\n", myurl, ret, nfs_get_error(options->context));
	}
	free(mnt_dir);
	nfs_destroy_url(nfs_url);
	return ret;
}
/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int fio_skeleton_init(struct thread_data *td)
{
	DEBUG_PRINT("fio_skeleton_init %p\n", td->eo);
	return 0;
}

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int fio_skeleton_setup(struct thread_data *td)
{
	DEBUG_PRINT("fio_skeleton_setup td=%p eo=%p \n", td, td->eo);
	td->o.use_thread = 0; // useful for debugging, but doesn't terminate
	return 0;
}
/*
 * This is paired with the ->init() function and is called when a thread is
 * done doing io. Should tear down anything setup by the ->init() function.
 * Not required.
 */
static void fio_skeleton_cleanup(struct thread_data *td)
{
	struct fio_skeleton_options *o = td->eo;
	DEBUG_PRINT("fio_skeleton_cleanup\n");
	nfs_umount(o->context);
	nfs_destroy_context(o->context);
	free(o->events);
}

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_open_file() as the handler.
 */
static int fio_skeleton_open(struct thread_data *td, struct fio_file *f)
{
	int ret;
	struct fio_skeleton_options *options = td->eo;
	struct nfs_data *nfs_data = NULL;
	DEBUG_PRINT("fio_skeleton_open(%s) eo=%p td->o.iodepth=%d nfs_url=%s nfs_write=%s nfs_read=%s nfs_trim=%s\n", f->file_name,
		td->eo, td->o.iodepth, options->nfs_url, options->nfs_write, options->nfs_read, options->nfs_trim);

	if (!options->nfs_url) {
		FAIL("Must set config vars: nfs_url\n");
	}

	ret = do_mount(td, options->nfs_url);

	if (ret != 0) {
		return ret;
	}
	nfs_data = malloc(sizeof(struct nfs_data));
	memset(nfs_data, 0, sizeof(struct nfs_data));
	nfs_data->options = options;

	if (strstr(f->file_name, "stat_mkdir_rmdir")) {
		DEBUG_PRINT("stat_touch_rm");
		options->read = queue_stat;
		options->write = queue_mkdir;
		options->trim = queue_rmdir;
		options->op_type = NFS_STAT_MKDIR_RMDIR;
		if (td->o.td_ddir == TD_DDIR_WRITE) {
			ret = nfs_mkdir(options->context, f->file_name);
			if (ret != 0) {
				FAIL("Failed to mkdir: %s\n", nfs_get_error(options->context));
			}
		}
	} else if (strstr(f->file_name, "stat_touch_rm")) {
		DEBUG_PRINT("stat_touch_rm");
		options->read = queue_stat;
		options->write = sync_touch;
		options->trim = queue_rm;
		options->op_type = NFS_STAT_TOUCH_RM;
		if (td->o.td_ddir == TD_DDIR_WRITE) {
			ret = nfs_mkdir(options->context, f->file_name);
			if (ret != 0) {
				FAIL("Failed to mkdir: %s\n", nfs_get_error(options->context));
			}
		}
	} else {
		int flags = 0;
		if (td->o.td_ddir == TD_DDIR_WRITE) {
			DEBUG_PRINT("O_CREAT\n");
			flags |= O_CREAT | O_RDWR;
		} else {
			DEBUG_PRINT("O_RDWR\n");

			flags |= O_RDWR;
		}
		ret = nfs_open(options->context, f->file_name, flags, &nfs_data->nfsfh);
		DEBUG_PRINT("fio_skeleton_open f=%p nfsfh=%p\n", f, nfs_data->nfsfh);

		if (ret != 0) {
			FAIL("Failed to open nfs file: %s\n", nfs_get_error(options->context));
		}
		options->read = queue_read;
		options->write = queue_write;
		options->op_type = NFS_READ_WRITE;
	}
	f->engine_data = nfs_data;
	return ret;
}

/*
 * Hook for doing so. See fio_skeleton_open().
 */
static int fio_skeleton_close(struct thread_data *td, struct fio_file *f)
{
	struct nfs_data *nfs_data = f->engine_data;
	struct fio_skeleton_options *o = nfs_data->options;
	int ret = 0;
	DEBUG_PRINT("fio_skeleton_close: f=%p nfsfh=%p\n", f, nfs_data->nfsfh);
	if (td->o.td_ddir == TD_DDIR_TRIM) {
		if (o->op_type == NFS_STAT_MKDIR_RMDIR || o->op_type == NFS_STAT_TOUCH_RM) {
			ret = nfs_rmdir(o->context, f->file_name);
			if (ret != 0) {
				FAIL("Failed to rmdir: %s\n", nfs_get_error(o->context));
			}
		}
	}
	if (nfs_data->nfsfh) {
		ret = nfs_close(o->context, nfs_data->nfsfh);
	}
	free(nfs_data);
	f->engine_data = NULL;
	return ret;
}

/*
 * Hook for writing out outstanding data.
 */
static int fio_skeleton_commit(struct thread_data *td) {
	DEBUG_PRINT("fio_skeleton_commit\n");
	nfs_event_loop(td, true);
	return 0;
}

/*
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine"); for (and only for) external engines.
 */
struct ioengine_ops ioengine = {
	.name		= "nfs",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_skeleton_setup,
	.init		= fio_skeleton_init,
	// .prep		= fio_skeleton_prep,
	.queue		= fio_skeleton_queue,
	.cancel		= fio_skeleton_cancel,
	.getevents	= fio_skeleton_getevents,
	.event		= fio_skeleton_event,
	.cleanup	= fio_skeleton_cleanup,
	.open_file	= fio_skeleton_open,
	.close_file	= fio_skeleton_close,
	.commit     = fio_skeleton_commit,
	.flags      = FIO_DISKLESSIO | FIO_NOEXTEND | FIO_NODISKUTIL,
	.options	= options,
	.option_struct_size	= sizeof(struct fio_skeleton_options),
};

static void fio_init fio_nfs_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_nfs_unregister(void)
{
	unregister_ioengine(&ioengine);
}

