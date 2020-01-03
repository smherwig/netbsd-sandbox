#	$NetBSD: Makefile,v 1.2.2.1 2015/02/04 21:32:46 martin Exp $

.include "../Makefile.inc"

KMOD=		secmodel_sandbox
SRCS=		secmodel_sandbox.c \
			sandbox_device.c \
			sandbox.c \
			sandbox_lua.c \
			sandbox_ruleset.c \
			sandbox_path.c \
			sandbox_ref.c \
			sandbox_vnode.c \
			sandbox_rule.c

CPPFLAGS+=	-I${S}/../external/mit/lua/dist/src \
		-I${S}/sys

.include <bsd.kmodule.mk>
