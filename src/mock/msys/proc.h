/*	$NetBSD: proc.h,v 1.320 2014/02/21 22:06:48 skrll Exp $	*/

/*-
 * Copyright (c) 2006, 2007, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
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

/*-
 * Copyright (c) 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)proc.h	8.15 (Berkeley) 5/19/95
 */

#ifndef _MSYS_PROC_H_
#define	_MSYS_PROC_H_

#include <sys/types.h>

#include <msys/queue.h>

#define MAXCOMLEN 255

/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 *
 * Field markings and the corresponding locks:
 *
 * a:	p_auxlock
 * k:	ktrace_mutex
 * l:	proc_lock
 * t:	p_stmutex
 * p:	p_lock
 * (:	updated atomically
 * ::	unlocked, stable
 */

struct proc {
	LIST_ENTRY(proc) p_list;	/* l: List of all processes */

	int		p_exitsig;	/* l: signal to send to parent on exit */
	int		p_flag;		/* p: PK_* flags */
	int		p_sflag;	/* p: PS_* flags */
	int		p_slflag;	/* s, l: PSL_* flags */
	int		p_lflag;	/* l: PL_* flags */
	int		p_stflag;	/* t: PST_* flags */
	char		p_stat;		/* p: S* process status. */
	char		p_trace_enabled;/* p: cached by syscall_intern() */
	char		p_pad1[2];	/*  unused */

	pid_t		p_pid;		/* :: Process identifier. */
	struct proc 	*p_pptr;	/* l: Pointer to parent process. */
	LIST_ENTRY(proc) p_sibling;	/* l: List of sibling processes. */
	LIST_HEAD(, proc) p_children;	/* l: List of children. */
/* The following fields are all zeroed upon creation in fork. */
#define	p_startzero	p_nlwps

	int 		p_nlwps;	/* p: Number of LWPs */
	int 		p_nzlwps;	/* p: Number of zombie LWPs */
	int		p_nrlwps;	/* p: Number running/sleeping LWPs */
	int		p_nlwpwait;	/* p: Number of LWPs in lwp_wait1() */
	int		p_ndlwps;	/* p: Number of detached LWPs */
	int 		p_nlwpid;	/* p: Next LWP ID */

	/* scheduling */
	void		*p_sched_info;	/* p: Scheduler-specific structure */
	unsigned int	p_forktime;

	int		p_traceflag;	/* k: Kernel trace points */
	void		*p_tracep;	/* k: Trace private data */
	void		*p_emuldata;	/* :: per-proc emul data, or NULL */
	pid_t		p_ppid;		/* :: cached parent pid */
	pid_t 		p_fpid;		/* :: forked pid */

/*
 * End area that is zeroed on creation
 */
#define	p_endzero	p_startcopy

/*
 * The following fields are all copied upon creation in fork.
 */
#define	p_startcopy	p_sigctx

	unsigned char   p_nice;		/* p: Process "nice" value */
	char		    p_comm[MAXCOMLEN+1];
};

#endif	/* !_MSYS_PROC_H_ */
