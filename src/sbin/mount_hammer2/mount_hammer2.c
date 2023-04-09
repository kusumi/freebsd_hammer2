/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2023 The DragonFly Project.  All rights reserved.
 * Copyright (c) 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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
 */

#include <sys/types.h>
#include <sys/mount.h>
#include <fs/hammer2/hammer2_mount.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <mntopts.h>

static int mount_hammer2(int argc, char **argv);
static void usage(const char *ctl, ...);

static struct mntopt mopts[] = {
	MOPT_STDOPTS,
	MOPT_UPDATE,
	MOPT_END,
};

int
main(int argc, char **argv)
{
	setprogname(argv[0]);
	return mount_hammer2(argc, argv);
}

static void
mount_hammer2_parseargs(int argc, char **argv,
	struct hammer2_mount_info *args, int *mntflags,
	char *canon_dev, char *canon_dir)
{
	char *tmp;
	int ch;

	memset(args, 0, sizeof(*args));
	*mntflags = MNT_RDONLY; /* currently write unsupported */
	optind = optreset = 1; /* Reset for parse of new argv. */
	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			getmntopts(optarg, mopts, mntflags, &args->hflags);
			break;
		case '?':
		default:
			usage("unknown option: -%c", ch);
			/* not reached */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage("missing parameter(s) (special[@label] node)");
		/* not reached */
	}

	/* Remove unnecessary slashes from the device path if any. */
	strlcpy(canon_dev, argv[0], MAXPATHLEN);
	rmslashes(canon_dev, canon_dev);

	/* Resolve the mountpoint with realpath(3). */
	if (checkpath(argv[1], canon_dir) != 0)
		err(1, "%s", argv[1]);

	/* Automatically add @DATA if no label specified. */
	if (strchr(canon_dev, '@') == NULL) {
		if (asprintf(&tmp, "%s@DATA", canon_dev) == -1)
			err(1, "asprintf");
		strlcpy(canon_dev, tmp, MAXPATHLEN);
		free(tmp);
	}

	/* Prefix if necessary. */
	if (!strchr(canon_dev, ':') && canon_dev[0] != '/' &&
	    canon_dev[0] != '@') {
		if (asprintf(&tmp, "/dev/%s", canon_dev) == -1)
			err(1, "asprintf");
		strlcpy(canon_dev, tmp, MAXPATHLEN);
		free(tmp);
	}

	args->volume = canon_dev;
	args->hflags = HMNT2_LOCAL; /* force local, not optional */
}

int
mount_hammer2(int argc, char **argv)
{
	struct hammer2_mount_info args;
	struct iovec *iov = NULL;
	char fstype[] = "hammer2";
	char canon_dev[MAXPATHLEN], canon_dir[MAXPATHLEN];
	int mntflags, iovlen = 0;

	mount_hammer2_parseargs(argc, argv, &args, &mntflags, canon_dev,
	    canon_dir);

	build_iovec(&iov, &iovlen, "fstype", fstype, (size_t)-1);
	build_iovec(&iov, &iovlen, "fspath", canon_dir, (size_t)-1);
	build_iovec(&iov, &iovlen, "from", args.volume, (size_t)-1);
	build_iovec(&iov, &iovlen, "hflags", &args.hflags, sizeof(args.hflags));

	if (nmount(iov, iovlen, mntflags) < 0)
		err(1, "%s", canon_dev);

	return (0);
}

static void
usage(const char *ctl, ...)
{
	va_list va;

	va_start(va, ctl);
	fprintf(stderr, "mount_hammer2: ");
	vfprintf(stderr, ctl, va);
	va_end(va);
	fprintf(stderr, "\n");
	fprintf(stderr, " mount_hammer2 [-o options] special[@label] node\n");
	fprintf(stderr, " mount_hammer2 [-o options] @label node\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n"
			" <standard_mount_options>\n"
	);
	exit(1);
}
