/*
 * Copyright (C) 2013  Mentor Graphics
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
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
#include <helper.h>
#include <pthread.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_IP_PARAM ip
#include "ust_pthread.h"

/**
 * Prevent tracepoints from triggering tracepoints internally,
 * i.e. from internal calls.
 */
static __thread int thread_in_trace;

int nesting_guard_is_thread_in_trace()
{
	return thread_in_trace;
}

void nesting_guard_set_thread_in_trace()
{
	thread_in_trace = 1;
}

void nesting_guard_reset_thread_in_trace()
{
	thread_in_trace = 0;
}

#define TRACEPOINT_NO_NESTING(tracepoint_before, func_call, tracepoint_after) \
	if (nesting_guard_is_thread_in_trace()) { \
		return func_call; \
	} \
	nesting_guard_set_thread_in_trace(); \
	tracepoint_before; \
	retval = func_call; \
	tracepoint_after; \
	nesting_guard_reset_thread_in_trace()

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	static int (*mutex_lock)(pthread_mutex_t *);
	int retval;

	if (!mutex_lock) {
		mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
		if (!mutex_lock) {
			if (nesting_guard_is_thread_in_trace()) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}

	TRACEPOINT_NO_NESTING(
		tracepoint(lttng_ust_pthread, pthread_mutex_lock_req, mutex, LTTNG_UST_CALLER_IP()),
		mutex_lock(mutex),
		tracepoint(lttng_ust_pthread, pthread_mutex_lock_acq, mutex, retval,
			LTTNG_UST_CALLER_IP()));
	return retval;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	static int (*mutex_trylock)(pthread_mutex_t *);
	int retval;

	if (!mutex_trylock) {
		mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
		if (!mutex_trylock) {
			if (nesting_guard_is_thread_in_trace()) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}

	TRACEPOINT_NO_NESTING(
		,
		mutex_trylock(mutex),
		tracepoint(lttng_ust_pthread, pthread_mutex_trylock, mutex, retval,
			LTTNG_UST_CALLER_IP()));
	return retval;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	static int (*mutex_unlock)(pthread_mutex_t *);
	int retval;

	if (!mutex_unlock) {
		mutex_unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
		if (!mutex_unlock) {
			if (nesting_guard_is_thread_in_trace()) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}

	TRACEPOINT_NO_NESTING(
		,
		mutex_unlock(mutex),
		tracepoint(lttng_ust_pthread, pthread_mutex_unlock, mutex, retval, LTTNG_UST_CALLER_IP()));
	return retval;
}

int pthread_cond_wait(pthread_cond_t * __restrict cond, pthread_mutex_t * __restrict mutex)
{
	static int (*cond_wait)(pthread_cond_t * __restrict cond, pthread_mutex_t * __restrict mutex);
	int retval;

	if (!cond_wait) {
		cond_wait = dlsym(RTLD_NEXT, "pthread_cond_wait");
		if (!cond_wait) {
			if (nesting_guard_is_thread_in_trace()) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}

	TRACEPOINT_NO_NESTING(
		tracepoint(lttng_ust_pthread, pthread_cond_wait_req, cond, mutex, LTTNG_UST_CALLER_IP()),
		cond_wait(cond, mutex),
		tracepoint(lttng_ust_pthread, pthread_cond_wait_acq, cond, mutex, retval,
			LTTNG_UST_CALLER_IP()));
	return retval;
}
