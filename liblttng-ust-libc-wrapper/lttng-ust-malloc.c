/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _GNU_SOURCE
/*
 * Do _not_ define _LGPL_SOURCE because we don't want to create a
 * circular dependency loop between this malloc wrapper, liburcu and
 * libc.
 */
#include <lttng/ust-dlfcn.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <urcu/system.h>
#include <urcu/uatomic.h>
#include <urcu/compiler.h>
#include <urcu/tls-compat.h>
#include <urcu/arch.h>
#include <lttng/align.h>
#include <helper.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_IP_PARAM ip
#include "ust_libc.h"

/**
 * Prevent tracepoints from triggering tracepoints internally,
 * i.e. from internal calls.
 */
static int ust_tp_lock;

static __attribute__((unused))
void ust_block_spin_lock(pthread_mutex_t *lock)
{
	/*
	 * The memory barrier within cmpxchg takes care of ordering
	 * memory accesses with respect to the start of the critical
	 * section.
	 */
	while (uatomic_cmpxchg(&ust_tp_lock, 0, 1) != 0)
		caa_cpu_relax();
}

static __attribute__((unused))
void ust_block_spin_unlock(pthread_mutex_t *lock)
{
	/*
	 * Ensure memory accesses within the critical section do not
	 * leak outside.
	 */
	cmm_smp_mb();
	uatomic_set(&ust_tp_lock, 0);
}

#define calloc static_calloc
#define pthread_mutex_lock ust_block_spin_lock
#define pthread_mutex_unlock ust_block_spin_unlock
static DEFINE_URCU_TLS(int, tp_nesting);
#undef pthread_mutex_unlock
#undef pthread_mutex_lock
#undef calloc

#define TRACEPOINT_NO_NESTING(func_call, tp_call) \
	URCU_TLS(tp_nesting)++; \
	func_call \
	if (URCU_TLS(tp_nesting) == 1) { \
		tp_call \
	} \
	URCU_TLS(tp_nesting)--;

#define STATIC_CALLOC_LEN 4096
static char static_calloc_buf[STATIC_CALLOC_LEN];
static unsigned long static_calloc_buf_offset;

struct alloc_functions {
	void *(*calloc)(size_t nmemb, size_t size);
	void *(*malloc)(size_t size);
	void (*free)(void *ptr);
	void *(*realloc)(void *ptr, size_t size);
	void *(*memalign)(size_t alignment, size_t size);
	int (*posix_memalign)(void **memptr, size_t alignment, size_t size);
};

static
struct alloc_functions cur_alloc;

/*
 * Make sure our own use of the LTS compat layer will not cause infinite
 * recursion by calling calloc.
 */

static
void *static_calloc(size_t nmemb, size_t size);

/*
 * pthread mutex replacement for URCU tls compat layer.
 */
static int ust_malloc_lock;

static __attribute__((unused))
void ust_malloc_spin_lock(pthread_mutex_t *lock)
{
	/*
	 * The memory barrier within cmpxchg takes care of ordering
	 * memory accesses with respect to the start of the critical
	 * section.
	 */
	while (uatomic_cmpxchg(&ust_malloc_lock, 0, 1) != 0)
		caa_cpu_relax();
}

static __attribute__((unused))
void ust_malloc_spin_unlock(pthread_mutex_t *lock)
{
	/*
	 * Ensure memory accesses within the critical section do not
	 * leak outside.
	 */
	cmm_smp_mb();
	uatomic_set(&ust_malloc_lock, 0);
}

#define calloc static_calloc
#define pthread_mutex_lock ust_malloc_spin_lock
#define pthread_mutex_unlock ust_malloc_spin_unlock
static DEFINE_URCU_TLS(int, malloc_nesting);
#undef pthread_mutex_unlock
#undef pthread_mutex_lock
#undef calloc

/*
 * Static allocator to use when initially executing dlsym(). It keeps a
 * size_t value of each object size prior to the object.
 */
static
void *static_calloc_aligned(size_t nmemb, size_t size, size_t alignment)
{
	size_t prev_offset, new_offset, res_offset, aligned_offset;

	if (nmemb * size == 0) {
		return NULL;
	}

	/*
	 * Protect static_calloc_buf_offset from concurrent updates
	 * using a cmpxchg loop rather than a mutex to remove a
	 * dependency on pthread. This will minimize the risk of bad
	 * interaction between mutex and malloc instrumentation.
	 */
	res_offset = CMM_LOAD_SHARED(static_calloc_buf_offset);
	do {
		prev_offset = res_offset;
		aligned_offset = ALIGN(prev_offset + sizeof(size_t), alignment);
		new_offset = aligned_offset + nmemb * size;
		if (new_offset > sizeof(static_calloc_buf)) {
			abort();
		}
	} while ((res_offset = uatomic_cmpxchg(&static_calloc_buf_offset,
			prev_offset, new_offset)) != prev_offset);
	*(size_t *) &static_calloc_buf[aligned_offset - sizeof(size_t)] = size;
	return &static_calloc_buf[aligned_offset];
}

static
void *static_calloc(size_t nmemb, size_t size)
{
	void *retval;

	retval = static_calloc_aligned(nmemb, size, 1);
	return retval;
}

static
void *static_malloc(size_t size)
{
	void *retval;

	retval = static_calloc_aligned(1, size, 1);
	return retval;
}

static
void static_free(void *ptr)
{
	/* no-op. */
}

static
void *static_realloc(void *ptr, size_t size)
{
	size_t *old_size = NULL;
	void *retval;

	if (size == 0) {
		retval = NULL;
		goto end;
	}

	if (ptr) {
		old_size = (size_t *) ptr - 1;
		if (size <= *old_size) {
			/* We can re-use the old entry. */
			*old_size = size;
			retval = ptr;
			goto end;
		}
	}
	/* We need to expand. Don't free previous memory location. */
	retval = static_calloc_aligned(1, size, 1);
	assert(retval);
	if (ptr)
		memcpy(retval, ptr, *old_size);
end:
	return retval;
}

static
void *static_memalign(size_t alignment, size_t size)
{
	void *retval;

	retval = static_calloc_aligned(1, size, alignment);
	return retval;
}

static
int static_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ptr;

	/* Check for power of 2, larger than void *. */
	if (alignment & (alignment - 1)
			|| alignment < sizeof(void *)
			|| alignment == 0) {
		goto end;
	}
	ptr = static_calloc_aligned(1, size, alignment);
	*memptr = ptr;
end:
	return 0;
}

static
void setup_static_allocator(void)
{
	assert(cur_alloc.calloc == NULL);
	cur_alloc.calloc = static_calloc;
	assert(cur_alloc.malloc == NULL);
	cur_alloc.malloc = static_malloc;
	assert(cur_alloc.free == NULL);
	cur_alloc.free = static_free;
	assert(cur_alloc.realloc == NULL);
	cur_alloc.realloc = static_realloc;
	assert(cur_alloc.memalign == NULL);
	cur_alloc.memalign = static_memalign;
	assert(cur_alloc.posix_memalign == NULL);
	cur_alloc.posix_memalign = static_posix_memalign;
}

static
void lookup_all_symbols(void)
{
	struct alloc_functions af;

	/*
	 * Temporarily redirect allocation functions to
	 * static_calloc_aligned, and free function to static_free
	 * (no-op), until the dlsym lookup has completed.
	 */
	setup_static_allocator();

	/* Perform the actual lookups */
	af.calloc = dlsym(RTLD_NEXT, "calloc");
	af.malloc = dlsym(RTLD_NEXT, "malloc");
	af.free = dlsym(RTLD_NEXT, "free");
	af.realloc = dlsym(RTLD_NEXT, "realloc");
	af.memalign = dlsym(RTLD_NEXT, "memalign");
	af.posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

	/* Populate the new allocator functions */
	memcpy(&cur_alloc, &af, sizeof(cur_alloc));
}

void *malloc(size_t size)
{
	void *retval;

	URCU_TLS(malloc_nesting)++;
	if (cur_alloc.malloc == NULL) {
		lookup_all_symbols();
		if (cur_alloc.malloc == NULL) {
			fprintf(stderr, "mallocwrap: unable to find malloc\n");
			abort();
		}
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_alloc.malloc(size);,
		if (URCU_TLS(malloc_nesting) == 1) {
			tracepoint(lttng_ust_libc, malloc,
				size, retval, LTTNG_UST_CALLER_IP());
		})
	URCU_TLS(malloc_nesting)--;
	return retval;
}

void free(void *ptr)
{
	URCU_TLS(malloc_nesting)++;
	/*
	 * Check whether the memory was allocated with
	 * static_calloc_align, in which case there is nothing to free.
	 */
	if (caa_unlikely((char *)ptr >= static_calloc_buf &&
			(char *)ptr < static_calloc_buf + STATIC_CALLOC_LEN)) {
		goto end;
	}

	TRACEPOINT_NO_NESTING(
		;,
		if (URCU_TLS(malloc_nesting) == 1) {
			tracepoint(lttng_ust_libc, free,
				ptr, LTTNG_UST_CALLER_IP());
		})

	if (cur_alloc.free == NULL) {
		lookup_all_symbols();
		if (cur_alloc.free == NULL) {
			fprintf(stderr, "mallocwrap: unable to find free\n");
			abort();
		}
	}
	cur_alloc.free(ptr);
end:
	URCU_TLS(malloc_nesting)--;
}

void *calloc(size_t nmemb, size_t size)
{
	void *retval;

	URCU_TLS(malloc_nesting)++;
	if (cur_alloc.calloc == NULL) {
		lookup_all_symbols();
		if (cur_alloc.calloc == NULL) {
			fprintf(stderr, "callocwrap: unable to find calloc\n");
			abort();
		}
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_alloc.calloc(nmemb, size);,
		if (URCU_TLS(malloc_nesting) == 1) {
			tracepoint(lttng_ust_libc, calloc,
				nmemb, size, retval, LTTNG_UST_CALLER_IP());
		})
	URCU_TLS(malloc_nesting)--;
	return retval;
}

void *realloc(void *ptr, size_t size)
{
	void *retval;

	URCU_TLS(malloc_nesting)++;
	/*
	 * Check whether the memory was allocated with
	 * static_calloc_align, in which case there is nothing
	 * to free, and we need to copy the old data.
	 */
	if (caa_unlikely((char *)ptr >= static_calloc_buf &&
			(char *)ptr < static_calloc_buf + STATIC_CALLOC_LEN)) {
		size_t *old_size;

		old_size = (size_t *) ptr - 1;
		if (cur_alloc.calloc == NULL) {
			lookup_all_symbols();
			if (cur_alloc.calloc == NULL) {
				fprintf(stderr, "reallocwrap: unable to find calloc\n");
				abort();
			}
		}
		retval = cur_alloc.calloc(1, size);
		if (retval) {
			memcpy(retval, ptr, *old_size);
		}
		/*
		 * Mimick that a NULL pointer has been received, so
		 * memory allocation analysis based on the trace don't
		 * get confused by the address from the static
		 * allocator.
		 */
		ptr = NULL;
		goto end;
	}

	if (cur_alloc.realloc == NULL) {
		lookup_all_symbols();
		if (cur_alloc.realloc == NULL) {
			fprintf(stderr, "reallocwrap: unable to find realloc\n");
			abort();
		}
	}
	retval = cur_alloc.realloc(ptr, size);
end:
	TRACEPOINT_NO_NESTING(
		;,
		if (URCU_TLS(malloc_nesting) == 1) {
			tracepoint(lttng_ust_libc, realloc,
				ptr, size, retval, LTTNG_UST_CALLER_IP());
		})
	URCU_TLS(malloc_nesting)--;
	return retval;
}

void *memalign(size_t alignment, size_t size)
{
	void *retval;

	URCU_TLS(malloc_nesting)++;
	if (cur_alloc.memalign == NULL) {
		lookup_all_symbols();
		if (cur_alloc.memalign == NULL) {
			fprintf(stderr, "memalignwrap: unable to find memalign\n");
			abort();
		}
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_alloc.memalign(alignment, size);,
		if (URCU_TLS(malloc_nesting) == 1) {
			tracepoint(lttng_ust_libc, memalign,
				alignment, size, retval,
				LTTNG_UST_CALLER_IP());
		})
	URCU_TLS(malloc_nesting)--;
	return retval;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int retval;

	URCU_TLS(malloc_nesting)++;
	if (cur_alloc.posix_memalign == NULL) {
		lookup_all_symbols();
		if (cur_alloc.posix_memalign == NULL) {
			fprintf(stderr, "posix_memalignwrap: unable to find posix_memalign\n");
			abort();
		}
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_alloc.posix_memalign(memptr, alignment, size);,
		if (URCU_TLS(malloc_nesting) == 1) {
			tracepoint(lttng_ust_libc, posix_memalign,
				*memptr, alignment, size,
				retval, LTTNG_UST_CALLER_IP());
		})
	URCU_TLS(malloc_nesting)--;
	return retval;
}

static
void lttng_ust_fixup_malloc_nesting_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(malloc_nesting)));
}

__attribute__((constructor))
void lttng_ust_malloc_wrapper_init(void)
{
	/* Initialization already done */
	if (cur_alloc.calloc) {
		return;
	}
	lttng_ust_fixup_malloc_nesting_tls();
	/*
	 * Ensure the allocator is in place before the process becomes
	 * multithreaded.
	 */
	lookup_all_symbols();
}

/*
 * Additions to libc-wrapper
 *
 * TODO(christophe.bedard) extract to separate file
 * TODO(christophe.bedard) remove these static_* functions if not necessary
 */

int static_accept(int fd, __SOCKADDR_ARG addr, socklen_t * addr_len)
{
	printf("static_accept called\n");
	return 0;
}

int static_accept4(int fd, __SOCKADDR_ARG addr, socklen_t * addr_len, int flags)
{
	printf("static_accept4 called\n");
	return 0;
}

int static_close(int fd)
{
	printf("static_close called\n");
	return 0;
}

int static_open(const char * path, int oflag, ...)
{
	printf("static_open called with path: %s\n", path);
	return 0;
}

int static_openat(int fd, const char * path, int oflag, ...)
{
	printf("static_openat called with path: %s\n", path);
	return 0;
}

FILE * static_fopen(const char * filename, const char * mode)
{
	printf("static_fopen called with filename: %s\n", filename);
	return NULL;
}

int static_poll(struct pollfd * fds, nfds_t nfds, int timeout)
{
	printf("static_poll called\n");
	return 0;
}

int static_ppoll(struct pollfd * fds, nfds_t nfds, const struct timespec * tmo_p, const sigset_t * sigmask)
{
	printf("static_ppoll called\n");
	return 0;
}

ssize_t static_read(int fd, void * buf, size_t count)
{
	printf("static_read called\n");
	return 0;
}

ssize_t static_pread(int fd, void * buf, size_t count, off_t offset)
{
	printf("static_pread called\n");
	return 0;
}

ssize_t static_pread64(int fd, void * buf, size_t count, off_t offset)
{
	printf("static_pread64 called\n");
	return 0;
}

ssize_t static_readv(int fd, const struct iovec * iov, int iovcnt)
{
	printf("static_readv called\n");
	return 0;
}

ssize_t static_preadv(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	printf("static_preadv called\n");
	return 0;
}

ssize_t static_preadv64(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	printf("static_preadv64 called\n");
	return 0;
}

int static_select(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout)
{
	printf("static_select called\n");
	return 0;
}

int static_pselect(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, const struct timespec * timeout, const sigset_t * sigmask)
{
	printf("static_pselect called\n");
	return 0;
}

ssize_t static_write(int fd, const void * buf, size_t count)
{
	printf("static_write called\n");
	return 0;
}

ssize_t static_pwrite(int fd, const void * buf, size_t count, off_t offset)
{
	printf("static_pwrite called\n");
	return 0;
}

ssize_t static_pwrite64(int fd, const void * buf, size_t count, off_t offset)
{
	printf("static_pwrite64 called\n");
	return 0;
}

ssize_t static_writev(int fd, const struct iovec * iov, int iovcnt)
{
	printf("static_writev called\n");
	return 0;
}

ssize_t static_pwritev(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	printf("static_pwritev called\n");
	return 0;
}

ssize_t static_pwritev64(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	printf("static_pwritev64 called\n");
	return 0;
}

struct syscall_functions {
	int (*accept)(int fd, struct sockaddr * addr, socklen_t * addr_len);
	int (*accept4)(int fd, struct sockaddr * addr, socklen_t * addr_len, int flags);
	int (*close)(int fd);
	int (*open)(const char * path, int oflag, ...);
	int (*open64)(const char * path, int oflag, ...);
	int (*openat)(int fd, const char * path, int oflag, ...);
	int (*openat64)(int fd, const char * path, int oflag, ...);
	FILE * (*fopen)(const char * filename, const char * mode);
	int (*poll)(struct pollfd * fds, nfds_t nfds, int timeout);
	int (*ppoll)(struct pollfd * fds, nfds_t nfds, const struct timespec * tmo_p, const sigset_t * sigmask);
	ssize_t (*read)(int fd, void * buf, size_t count);
	ssize_t (*pread)(int fd, void * buf, size_t count, off_t offset);
	ssize_t (*pread64)(int fd, void * buf, size_t count, off_t offset);
	ssize_t (*readv)(int fd, const struct iovec * iov, int iovcnt);
	ssize_t (*preadv)(int fd, const struct iovec * iov, int iovcnt, off_t offset);
	ssize_t (*preadv64)(int fd, const struct iovec * iov, int iovcnt, off_t offset);
	int (*select)(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout);
	int (*pselect)(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, const struct timespec * timeout, const sigset_t * sigmask);
	ssize_t (*write)(int fd, const void * buf, size_t count);
	ssize_t (*pwrite)(int fd, const void * buf, size_t count, off_t offset);
	ssize_t (*pwrite64)(int fd, const void * buf, size_t count, off_t offset);
	ssize_t (*writev)(int fd, const struct iovec * iov, int iovcnt);
	ssize_t (*pwritev)(int fd, const struct iovec * iov, int iovcnt, off_t offset);
	ssize_t (*pwritev64)(int fd, const struct iovec * iov, int iovcnt, off_t offset);
};

static
struct syscall_functions cur_syscall;

static
void setup_static_sycalls(void)
{
	assert(NULL == cur_syscall.accept);
	cur_syscall.accept = static_accept;
	assert(NULL == cur_syscall.accept4);
	cur_syscall.accept4 = static_accept4;
	assert(NULL == cur_syscall.close);
	cur_syscall.close = static_close;
	assert(NULL == cur_syscall.open);
	cur_syscall.open = static_open;
	assert(NULL == cur_syscall.open64);
	cur_syscall.open64 = static_open;
	assert(NULL == cur_syscall.openat);
	cur_syscall.openat = static_openat;
	assert(NULL == cur_syscall.openat64);
	cur_syscall.openat64 = static_openat;
	assert(NULL == cur_syscall.fopen);
	cur_syscall.fopen = static_fopen;
	assert(NULL == cur_syscall.poll);
	cur_syscall.poll = static_poll;
	assert(NULL == cur_syscall.ppoll);
	cur_syscall.ppoll = static_ppoll;
	assert(NULL == cur_syscall.read);
	cur_syscall.read = static_read;
	assert(NULL == cur_syscall.pread);
	cur_syscall.pread = static_pread;
	assert(NULL == cur_syscall.pread64);
	cur_syscall.pread64 = static_pread64;
	assert(NULL == cur_syscall.readv);
	cur_syscall.readv = static_readv;
	assert(NULL == cur_syscall.preadv);
	cur_syscall.preadv = static_preadv;
	assert(NULL == cur_syscall.preadv64);
	cur_syscall.preadv64 = static_preadv64;
	assert(NULL == cur_syscall.select);
	cur_syscall.select = static_select;
	assert(NULL == cur_syscall.pselect);
	cur_syscall.pselect = static_pselect;
	assert(NULL == cur_syscall.write);
	cur_syscall.write = static_write;
	assert(NULL == cur_syscall.pwrite);
	cur_syscall.pwrite = static_pwrite;
	assert(NULL == cur_syscall.pwrite64);
	cur_syscall.pwrite64 = static_pwrite64;
	assert(NULL == cur_syscall.writev);
	cur_syscall.writev = static_writev;
	assert(NULL == cur_syscall.pwritev);
	cur_syscall.pwritev = static_pwritev;
	assert(NULL == cur_syscall.pwritev64);
	cur_syscall.pwritev64 = static_pwritev64;
}

static
void lookup_all_syscall_symbols(void)
{
	struct syscall_functions sf;

	/*
	 * Temporarily redirect syscall functions
	 * until the dlsym lookup has completed.
	 */
	setup_static_sycalls();

	/* Perform the actual lookups */

	sf.accept = dlsym(RTLD_NEXT, "accept");
	sf.accept4 = dlsym(RTLD_NEXT, "accept4");
	sf.close = dlsym(RTLD_NEXT, "close");
	sf.open = dlsym(RTLD_NEXT, "open");
	sf.open64 = dlsym(RTLD_NEXT, "open64");
	sf.openat = dlsym(RTLD_NEXT, "openat");
	sf.openat64 = dlsym(RTLD_NEXT, "openat64");
	sf.fopen = dlsym(RTLD_NEXT, "fopen");
	sf.poll = dlsym(RTLD_NEXT, "poll");
	sf.ppoll = dlsym(RTLD_NEXT, "ppoll");
	sf.read = dlsym(RTLD_NEXT, "read");
	sf.pread = dlsym(RTLD_NEXT, "pread");
	sf.pread64 = dlsym(RTLD_NEXT, "pread64");
	sf.readv = dlsym(RTLD_NEXT, "readv");
	sf.preadv = dlsym(RTLD_NEXT, "preadv");
	sf.preadv64 = dlsym(RTLD_NEXT, "preadv64");
	sf.select = dlsym(RTLD_NEXT, "select");
	sf.pselect = dlsym(RTLD_NEXT, "pselect");
	sf.write = dlsym(RTLD_NEXT, "write");
	sf.pwrite = dlsym(RTLD_NEXT, "pwrite");
	sf.pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
	sf.writev = dlsym(RTLD_NEXT, "writev");
	sf.pwritev = dlsym(RTLD_NEXT, "pwritev");
	sf.pwritev64 = dlsym(RTLD_NEXT, "pwritev64");

	/* Populate the new allocator functions */
	memcpy(&cur_syscall, &sf, sizeof(cur_syscall));
}


int accept(int fd, struct sockaddr * addr, socklen_t * addr_len)
{
	int retval;

	if (NULL == cur_syscall.accept) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.accept) {
			fprintf(stderr, "accept: unable to find accept\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.accept(fd, addr, addr_len);,
		tracepoint(lttng_ust_libc, accept, fd, addr, addr_len, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int accept4(int fd, struct sockaddr * addr, socklen_t * addr_len, int flags)
{
	int retval;

	if (NULL == cur_syscall.accept4) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.accept4) {
			fprintf(stderr, "accept4: unable to find accept4\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.accept4(fd, addr, addr_len, flags);,
		tracepoint(lttng_ust_libc, accept4, fd, addr, addr_len, flags, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int close(int fd)
{
	int retval;

	if (NULL == cur_syscall.close) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.close) {
			fprintf(stderr, "close: unable to find close\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.close(fd);,
		tracepoint(lttng_ust_libc, close, fd, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int open(const char * path, int oflag, ...)
{
	int retval;

	if (NULL == cur_syscall.open) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.open) {
			fprintf(stderr, "open: unable to find open\n");
			abort();
		}
	}

	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(oflag)) {
		va_list arg;
		va_start(arg, oflag);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.open(path, oflag, mode);,
		tracepoint(lttng_ust_libc, open, path, oflag, mode, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int open64(const char * path, int oflag, ...)
{
	int retval;

	if (NULL == cur_syscall.open64) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.open64) {
			fprintf(stderr, "open64: unable to find open64\n");
			abort();
		}
	}

	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(oflag)) {
		va_list arg;
		va_start(arg, oflag);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.open64(path, oflag, mode);,
		tracepoint(lttng_ust_libc, open64, path, oflag, mode, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int openat(int fd, const char * path, int oflag, ...)
{
	int retval;

	if (NULL == cur_syscall.openat) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.openat) {
			fprintf(stderr, "openat: unable to find openat\n");
			abort();
		}
	}

	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(oflag)) {
		va_list arg;
		va_start(arg, oflag);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.openat(fd, path, oflag, mode);,
		tracepoint(lttng_ust_libc, openat, fd, path, oflag, mode, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int openat64(int fd, const char * path, int oflag, ...)
{
	int retval;

	if (NULL == cur_syscall.openat64) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.openat64) {
			fprintf(stderr, "openat64: unable to find openat64\n");
			abort();
		}
	}

	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(oflag)) {
		va_list arg;
		va_start(arg, oflag);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.openat64(fd, path, oflag, mode);,
		tracepoint(lttng_ust_libc, openat64, fd, path, oflag, mode, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

FILE * fopen(const char * filename, const char * mode)
{
	FILE * ret;

	if (NULL == cur_syscall.fopen) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.fopen) {
			fprintf(stderr, "fopen: unable to find fopen\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		ret = cur_syscall.fopen(filename, mode);,
		tracepoint(lttng_ust_libc, fopen, filename, mode, ret, LTTNG_UST_CALLER_IP());)
	return ret;
}

int poll(struct pollfd * fds, nfds_t nfds, int timeout)
{
	int retval;

	if (NULL == cur_syscall.poll) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.poll) {
			fprintf(stderr, "poll: unable to find poll\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.poll(fds, nfds, timeout);,
		tracepoint(lttng_ust_libc, poll, fds, nfds, timeout, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int ppoll(struct pollfd * fds, nfds_t nfds, const struct timespec * tmo_p, const sigset_t * sigmask)
{
	int retval;

	if (NULL == cur_syscall.ppoll) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.ppoll) {
			fprintf(stderr, "ppoll: unable to find ppoll\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.ppoll(fds, nfds, tmo_p, sigmask);,
		tracepoint(lttng_ust_libc, ppoll, fds, nfds, tmo_p, sigmask, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t read(int fd, void * buf, size_t count)
{
	int retval;

	if (NULL == cur_syscall.read) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.read) {
			fprintf(stderr, "read: unable to find read\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.read(fd, buf, count);,
		tracepoint(lttng_ust_libc, read, fd, buf, count, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t pread(int fd, void * buf, size_t count, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.pread) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pread) {
			fprintf(stderr, "pread: unable to find pread\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pread(fd, buf, count, offset);,
		tracepoint(lttng_ust_libc, pread, fd, buf, count, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t pread64(int fd, void * buf, size_t count, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.pread64) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pread64) {
			fprintf(stderr, "pread64: unable to find pread64\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pread64(fd, buf, count, offset);,
		tracepoint(lttng_ust_libc, pread64, fd, buf, count, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t readv(int fd, const struct iovec * iov, int iovcnt)
{
	int retval;

	if (NULL == cur_syscall.readv) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.readv) {
			fprintf(stderr, "readv: unable to find readv\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.readv(fd, iov, iovcnt);,
		tracepoint(lttng_ust_libc, readv, fd, iov, iovcnt, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t preadv(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.preadv) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.preadv) {
			fprintf(stderr, "preadv: unable to find preadv\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.preadv(fd, iov, iovcnt, offset);,
		tracepoint(lttng_ust_libc, preadv, fd, iov, iovcnt, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t preadv64(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.preadv64) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.preadv64) {
			fprintf(stderr, "preadv64: unable to find preadv64\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.preadv64(fd, iov, iovcnt, offset);,
		tracepoint(lttng_ust_libc, preadv64, fd, iov, iovcnt, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int select(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout)
{
	int retval;

	if (NULL == cur_syscall.select) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.select) {
			fprintf(stderr, "select: unable to find select\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.select(nfds, readfds, writefds, exceptfds, timeout);,
		tracepoint(lttng_ust_libc, select, nfds, readfds, writefds, exceptfds, timeout, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

int pselect(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, const struct timespec * timeout, const sigset_t * sigmask)
{
	int retval;

	if (NULL == cur_syscall.pselect) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pselect) {
			fprintf(stderr, "pselect: unable to find pselect\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);,
		tracepoint(lttng_ust_libc, pselect, nfds, readfds, writefds, exceptfds, timeout, sigmask, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t write(int fd, const void * buf, size_t count)
{
	int retval;

	if (NULL == cur_syscall.write) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.write) {
			fprintf(stderr, "write: unable to find write\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.write(fd, buf, count);,
		tracepoint(lttng_ust_libc, write, fd, buf, count, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t pwrite(int fd, const void * buf, size_t count, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.pwrite) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pwrite) {
			fprintf(stderr, "pwrite: unable to find pwrite\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pwrite(fd, buf, count, offset);,
		tracepoint(lttng_ust_libc, pwrite, fd, buf, count, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t pwrite64(int fd, const void * buf, size_t count, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.pwrite64) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pwrite64) {
			fprintf(stderr, "pwrite64: unable to find pwrite64\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pwrite64(fd, buf, count, offset);,
		tracepoint(lttng_ust_libc, pwrite64, fd, buf, count, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t writev(int fd, const struct iovec * iov, int iovcnt)
{
	int retval;

	if (NULL == cur_syscall.writev) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.writev) {
			fprintf(stderr, "writev: unable to find writev\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.writev(fd, iov, iovcnt);,
		tracepoint(lttng_ust_libc, writev, fd, iov, iovcnt, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t pwritev(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.pwritev) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pwritev) {
			fprintf(stderr, "pwritev: unable to find pwritev\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pwritev(fd, iov, iovcnt, offset);,
		tracepoint(lttng_ust_libc, pwritev, fd, iov, iovcnt, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

ssize_t pwritev64(int fd, const struct iovec * iov, int iovcnt, off_t offset)
{
	int retval;

	if (NULL == cur_syscall.pwritev64) {
		lookup_all_syscall_symbols();
		if (NULL == cur_syscall.pwritev64) {
			fprintf(stderr, "pwritev64: unable to find pwritev64\n");
			abort();
		}
	}

	TRACEPOINT_NO_NESTING(
		retval = cur_syscall.pwritev64(fd, iov, iovcnt, offset);,
		tracepoint(lttng_ust_libc, pwritev64, fd, iov, iovcnt, offset, retval, LTTNG_UST_CALLER_IP());)
	return retval;
}

static
void lttng_ust_fixup_tp_nesting_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(tp_nesting)));
}

__attribute__((constructor))
void lttng_ust_libc_wrapper_init(void)
{
	/* Initialization already done */
	if (cur_syscall.open) {
		return;
	}
	lttng_ust_fixup_tp_nesting_tls();
	/*
	 * Ensure the it is in place before the process becomes
	 * multithreaded.
	 */
	lookup_all_syscall_symbols();
}
