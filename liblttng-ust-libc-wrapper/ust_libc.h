#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_libc

#if !defined(_TRACEPOINT_UST_LIBC_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_LIBC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(lttng_ust_libc, malloc,
	TP_ARGS(size_t, size, void *, ptr, void *, ip),
	TP_FIELDS(
		ctf_integer(size_t, size, size)
		ctf_integer_hex(void *, ptr, ptr)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, free,
	TP_ARGS(void *, ptr, void *, ip),
	TP_FIELDS(
		ctf_integer_hex(void *, ptr, ptr)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, calloc,
	TP_ARGS(size_t, nmemb, size_t, size, void *, ptr, void *, ip),
	TP_FIELDS(
		ctf_integer(size_t, nmemb, nmemb)
		ctf_integer(size_t, size, size)
		ctf_integer_hex(void *, ptr, ptr)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, realloc,
	TP_ARGS(void *, in_ptr, size_t, size, void *, ptr, void *, ip),
	TP_FIELDS(
		ctf_integer_hex(void *, in_ptr, in_ptr)
		ctf_integer(size_t, size, size)
		ctf_integer_hex(void *, ptr, ptr)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, memalign,
	TP_ARGS(size_t, alignment, size_t, size, void *, ptr, void *, ip),
	TP_FIELDS(
		ctf_integer(size_t, alignment, alignment)
		ctf_integer(size_t, size, size)
		ctf_integer_hex(void *, ptr, ptr)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, posix_memalign,
	TP_ARGS(void *, out_ptr, size_t, alignment, size_t, size, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer_hex(void *, out_ptr, out_ptr)
		ctf_integer(size_t, alignment, alignment)
		ctf_integer(size_t, size, size)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, accept,
	TP_ARGS(int, fd, void *, addr_ptr, void *, addr_len_ptr, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(void *, addr_ptr, addr_ptr)
		ctf_integer_hex(void *, addr_len_ptr, addr_len_ptr)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, accept4,
	TP_ARGS(int, fd, void *, addr_ptr, void *, addr_len_ptr, int, flags, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(void *, addr_ptr, addr_ptr)
		ctf_integer_hex(void *, addr_len_ptr, addr_len_ptr)
		ctf_integer(int, flags, flags)
		ctf_integer(int, result, result)
	)
)

// TODO add fclose
TRACEPOINT_EVENT(lttng_ust_libc, close,
	TP_ARGS(int, fd, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, open,
	TP_ARGS(const char *, path, int, oflag, int, mode, int, result, void *, ip),
	TP_FIELDS(
		ctf_string(path, path)
		ctf_integer(int, oflag, oflag)
		ctf_integer(int, mode, mode)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, open64,
	TP_ARGS(const char *, path, int, oflag, int, mode, int, result, void *, ip),
	TP_FIELDS(
		ctf_string(path, path)
		ctf_integer(int, oflag, oflag)
		ctf_integer(int, mode, mode)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, openat,
	TP_ARGS(int, fd, const char *, path, int, oflag, int, mode, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_string(path, path)
		ctf_integer(int, oflag, oflag)
		ctf_integer(int, mode, mode)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, openat64,
	TP_ARGS(int, fd, const char *, path, int, oflag, int, mode, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_string(path, path)
		ctf_integer(int, oflag, oflag)
		ctf_integer(int, mode, mode)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, fopen,
	TP_ARGS(const char *, filename, const char *, mode, void *, result, void *, ip),
	TP_FIELDS(
		ctf_string(filename, filename)
		ctf_string(mode, mode)
		ctf_integer_hex(void *, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, poll,
	TP_ARGS(void *, fds_ptr, unsigned long int, nfds, int, timeout, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer_hex(void *, fds_ptr, fds_ptr)
		ctf_integer(unsigned long int, nfds, nfds)
		ctf_integer(int, timeout, timeout)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, ppoll,
	TP_ARGS(void *, fds_ptr, unsigned long int, nfds, const void *, tmo_p_ptr, const void *, sigmask_ptr, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer_hex(void *, fds_ptr, fds_ptr)
		ctf_integer(unsigned long int, nfds, nfds)
		ctf_integer_hex(const void *, tmo_p_ptr, tmo_p_ptr)
		ctf_integer_hex(const void *, sigmask_ptr, sigmask_ptr)
		ctf_integer(int, result, result)
	)
)

// TODO add fread
TRACEPOINT_EVENT(lttng_ust_libc, read,
	TP_ARGS(int, fd, void *, buf, size_t, count, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(void *, buf, buf)
		ctf_integer(size_t, count, count)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pread,
	TP_ARGS(int, fd, void *, buf, size_t, count, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(void *, buf, buf)
		ctf_integer(size_t, count, count)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pread64,
	TP_ARGS(int, fd, void *, buf, size_t, count, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(void *, buf, buf)
		ctf_integer(size_t, count, count)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, readv,
	TP_ARGS(int, fd, const void *, iov_ptr, int, iovcnt, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, iov_ptr, iov_ptr)
		ctf_integer(int, iovcnt, iovcnt)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, preadv,
	TP_ARGS(int, fd, const void *, iov_ptr, int, iovcnt, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, iov_ptr, iov_ptr)
		ctf_integer(int, iovcnt, iovcnt)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, preadv64,
	TP_ARGS(int, fd, const void *, iov_ptr, int, iovcnt, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, iov_ptr, iov_ptr)
		ctf_integer(int, iovcnt, iovcnt)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, select,
	TP_ARGS(int, nfds, void *, readfds_ptr, void *, writefds_ptr, void *, exceptfds_ptr, void *, timeout_ptr, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, nfds, nfds)
		ctf_integer_hex(void *, readfds_ptr, readfds_ptr)
		ctf_integer_hex(void *, writefds_ptr, writefds_ptr)
		ctf_integer_hex(void *, exceptfds_ptr, exceptfds_ptr)
		ctf_integer_hex(void *, timeout_ptr, timeout_ptr)
		ctf_integer(int, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pselect,
	TP_ARGS(int, nfds, void *, readfds_ptr, void *, writefds_ptr, void *, exceptfds_ptr, const void *, timeout_ptr, const void *, sigmask_ptr, int, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, nfds, nfds)
		ctf_integer_hex(void *, readfds_ptr, readfds_ptr)
		ctf_integer_hex(void *, writefds_ptr, writefds_ptr)
		ctf_integer_hex(void *, exceptfds_ptr, exceptfds_ptr)
		ctf_integer_hex(const void *, timeout_ptr, timeout_ptr)
		ctf_integer_hex(const void *, sigmask_ptr, sigmask_ptr)
		ctf_integer(int, result, result)
	)
)

// TODO add fwrite
TRACEPOINT_EVENT(lttng_ust_libc, write,
	TP_ARGS(int, fd, const void *, buf, size_t, count, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, buf, buf)
		ctf_integer(size_t, count, count)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pwrite,
	TP_ARGS(int, fd, const void *, buf, size_t, count, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, buf, buf)
		ctf_integer(size_t, count, count)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pwrite64,
	TP_ARGS(int, fd, const void *, buf, size_t, count, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, buf, buf)
		ctf_integer(size_t, count, count)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, writev,
	TP_ARGS(int, fd, const void *, iov_ptr, int, iovcnt, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, iov_ptr, iov_ptr)
		ctf_integer(int, iovcnt, iovcnt)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pwritev,
	TP_ARGS(int, fd, const void *, iov_ptr, int, iovcnt, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, iov_ptr, iov_ptr)
		ctf_integer(int, iovcnt, iovcnt)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

TRACEPOINT_EVENT(lttng_ust_libc, pwritev64,
	TP_ARGS(int, fd, const void *, iov_ptr, int, iovcnt, off_t, offset, ssize_t, result, void *, ip),
	TP_FIELDS(
		ctf_integer(int, fd, fd)
		ctf_integer_hex(const void *, iov_ptr, iov_ptr)
		ctf_integer(int, iovcnt, iovcnt)
		ctf_integer(off_t, offset, offset)
		ctf_integer(ssize_t, result, result)
	)
)

#endif /* _TRACEPOINT_UST_LIBC_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_libc.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
