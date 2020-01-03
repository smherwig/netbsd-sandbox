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
