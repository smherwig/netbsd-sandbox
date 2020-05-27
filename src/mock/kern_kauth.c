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

#include <msys/types.h>
#include <msys/systm.h>
#include <msys/kmem.h>
#include <msys/kauth.h>

#include <sys/types.h>

kauth_cred_t 
kauth_cred_alloc(void)
{
    struct kauth_cred *cred = NULL;

    cred = kmem_zalloc(sizeof(*cred), KM_SLEEP);
    cred->refcnt = 1;
	cred->cr_uid = 4;
	cred->cr_euid = 5;
	cred->cr_svuid = 6;
	cred->cr_gid = 7;
	cred->cr_egid = 8;
	cred->cr_svgid = 9;
	cred->cr_ngroups = 0;

    return (cred);
}

void
kauth_cred_free(kauth_cred_t cred)
{
    cred->refcnt--;
    if (cred->refcnt == 0)
        kmem_free(cred, sizeof(*cred));
}

uid_t
kauth_cred_getuid(kauth_cred_t cred)
{
	return (cred->cr_uid);
}

uid_t
kauth_cred_geteuid(kauth_cred_t cred)
{
	return (cred->cr_euid);
}

uid_t
kauth_cred_getsvuid(kauth_cred_t cred)
{
	return (cred->cr_svuid);
}

gid_t
kauth_cred_getgid(kauth_cred_t cred)
{
	return (cred->cr_gid);
}

gid_t
kauth_cred_getegid(kauth_cred_t cred)
{
	return (cred->cr_egid);
}

gid_t
kauth_cred_getsvgid(kauth_cred_t cred)
{
	return (cred->cr_svgid);
}

u_int
kauth_cred_ngroups(kauth_cred_t cred)
{
	KASSERT(cred != NULL);

	return (cred->cr_ngroups);
}

/*
 * Return the group at index idx from the groups in cred.
 */
gid_t
kauth_cred_group(kauth_cred_t cred, u_int idx)
{
	KASSERT(cred != NULL);
	KASSERT(idx < cred->cr_ngroups);

	return (cred->cr_groups[idx]);
}
