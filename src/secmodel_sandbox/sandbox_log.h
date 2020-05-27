/*-
 * Copyright (c) 2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SANDBOX_LOG_
#define _SANDBOX_LOG_

#include <sys/systm.h>

#define SANDBOX_LOG_LEVEL_NONE     0
#define SANDBOX_LOG_LEVEL_ERROR    1
#define SANDBOX_LOG_LEVEL_WARN     2
#define SANDBOX_LOG_LEVEL_INFO     3
#define SANDBOX_LOG_LEVEL_DEBUG    4
#define SANDBOX_LOG_LEVEL_TRACE    5

#define SANDBOX_LOG_LEVEL SANDBOX_LOG_LEVEL_INFO
#define SANDBOX_PRINTF printf

#if SANDBOX_LOG_LEVEL >= SANDBOX_LOG_LEVEL_ERROR
    #define SANDBOX_LOG_ERROR(fmt, ...) \
        SANDBOX_PRINTF("E %s:%d:%s " fmt, strrchr(__FILE__, '/') + 1, __LINE__, __func__,##__VA_ARGS__)
#else
    #define SANDBOX_LOG_ERROR(fmt, ...) ((void) 0)
#endif

#if SANDBOX_LOG_LEVEL >= SANDBOX_LOG_LEVEL_WARN
    #define SANDBOX_LOG_WARN(fmt, ...) \
        SANDBOX_PRINTF("W %s:%d:%s " fmt, strrchr(__FILE__, '/') + 1,  __LINE__, __func__,##__VA_ARGS__)
#else
    #define SANDBOX_LOG_WARN(fmt, ...) ((void) 0)
#endif

#if SANDBOX_LOG_LEVEL >= SANDBOX_LOG_LEVEL_INFO
    #define SANDBOX_LOG_INFO(fmt, ...) \
        SANDBOX_PRINTF("I %s:%d:%s " fmt, strrchr(__FILE__, '/') + 1, __LINE__, __func__,##__VA_ARGS__)
#else
    #define SANDBOX_LOG_INFO(fmt, ...) ((void) 0)
#endif

#if SANDBOX_LOG_LEVEL >= SANDBOX_LOG_LEVEL_DEBUG
    #define SANDBOX_LOG_DEBUG(fmt, ...) \
        SANDBOX_PRINTF("D %s:%d:%s " fmt, strrchr(__FILE__, '/') + 1 ,__LINE__, __func__,##__VA_ARGS__)
#else
    #define SANDBOX_LOG_DEBUG(fmt, ...) ((void) 0)
#endif

#if SANDBOX_LOG_LEVEL >= SANDBOX_LOG_LEVEL_TRACE
    #define SANDBOX_LOG_TRACE_ENTER \
        SANDBOX_PRINTF("> %s\n", __func__)
    #define SANDBOX_LOG_TRACE_EXIT \
        SANDBOX_PRINTF("< %s\n", __func__)
#else
    #define SANDBOX_LOG_TRACE_ENTER ((void) 0)
    #define SANDBOX_LOG_TRACE_EXIT  ((void) 0)
#endif

#endif /* ! _SANDBOX_LOG_H_ */
