/*****************************************************************************
 *
 * $Id: utmp.c,v 1.7 2004/12/28 15:30:53 mbse Exp $
 * Purpose ...............: MBSE BBS Shadow Password Suite
 * Original Source .......: Shadow Password Suite
 * Original Copyright ....: Julianne Frances Haugh and others.
 *
 *****************************************************************************
 * Copyright (C) 1997-2002
 *   
 * Michiel Broek                FIDO:           2:280/2802
 * Beekmansbos 10
 * 1971 BV IJmuiden
 * the Netherlands
 *
 * This file is part of MBSE BBS.
 *
 * This BBS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * MBSE BBS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with MBSE BBS; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *****************************************************************************/

#include "../config.h"
#include "mblogin.h"

#if HAVE_UTMP_H
#include <utmp.h>
#endif

#if HAVE_UTMPX_H
#if defined(__GLIBC__) && (__GLIBC__ > 2 ||  (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1))
# define __USE_GNU /* use to access updwtmpx */
#endif
#include <utmpx.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#if HAVE_UTIL_H
#include <util.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include "utmp.h"

#if defined(__FreeBSD__)
#  if !defined(_PATH_WTMP)
#    define _PATH_WTMP "" /* Not Used */
#  endif
#endif /* __FreeBSD__ */
#if HAVE_UTMPX_H
extern	struct	utmpx	utxent;
#elif defined(HAVE_UTMP_H)
extern	struct	utmp	utent;
#endif


#define	NO_UTENT \
	"No utmp entry.  You must exec \"login\" from the lowest level \"sh\""
#define	NO_TTY \
	"Unable to determine your tty name."

#if HAVE_UTMPX_H 
int find_by_current_pid(struct utmpx *utx_out)
{
	pid_t pid = getpid();
	struct utmpx *utx = NULL;
	int found = 0;

	if (NULL == utx_out)
		return -1;

	setutxent();

	while (NULL != (utx = getutxent())) {
		if (utx->ut_pid == pid) {
			memcpy(utx_out, utx, sizeof(struct utmpx));
			found = 1;
			break;
		}
	}

	endutxent();
	return found ? 0 : -1;
}

void create_utx_entry(struct utmpx *output) {
	char *line;
	struct timespec tp;

	if (NULL == output) {
		puts("No output defined for create_utx_entry()");
		exit(1);
	}

	/*
	 * Hand-craft a new utmp entry.
	 */
	memset(output, 0, sizeof(struct utmpx));

	if (! (line = ttyname (0))) {
		puts (NO_TTY);
		exit (1);
	}
	if (strncmp (line, "/dev/", 5) == 0)
		line += 5;

	memccpy(output->ut_line, line, '\0', sizeof(output->ut_line));
	memccpy(output->ut_user, "LOGIN", '\0', sizeof(output->ut_user));
	output->ut_pid = getpid();
	output->ut_type = USER_PROCESS; /* FreeBSD doesn't process LOGIN_PROCESS types */
	clock_gettime(CLOCK_REALTIME, &tp);
	output->ut_tv.tv_sec = tp.tv_sec;
	output->ut_tv.tv_usec = tp.tv_nsec / 1000;

}

# ifndef __FreeBSD__
/* Currently:
 * NetBSD >= circa 1.6
 * FreeBSD >= 9.0
 * Linux(glibc) >= circa glibc v2.1 or 2.2
 * 
 * Support this interface.
 */
void checkutmp(int isroot) {
	char *line;
	struct utmpx utx = {0};

	if (isroot) {
		if (0 == find_by_current_pid(&utx)) {
 			puts(NO_UTENT);
			exit(1);
		}

		/*
		 * If there is no ut_line value in this record, fill
		 * it in by getting the TTY name and stuffing it in
		 * the structure.  The UNIX/PC is broken in this regard
		 * and needs help ...
		 */

		if (utxent.ut_line[0] == '\0')
		{
			if (!(line = ttyname(0))) {
				puts(NO_TTY);
				exit(1);
			}
			if (strncmp(line, "/dev/", 5) == 0)
				line += 5;
			strncpy(utxent.ut_line, line, sizeof utxent.ut_line);
		}
	} else {
		create_utx_entry(&utxent);
	}
}
# else /* FreeBSD Only below */
/*
 * Also used for FreeBSD
 * FreeBSD does not process LOGIN_PROCESS, the existence of a 
 * entry may not be possible.
 */
void checkutmp(int picky)
{
	create_utx_entry(&utxent);
}

void updwtmpx(const char *filename, const struct utmpx *input) {
	/* Dummy function, not needed on FreeBSD */
}

# endif 
void setutmp(const char *name, const char *line, const char *host) {
	struct utmpx utx;

	if (0 != find_by_current_pid(&utx)) {
		create_utx_entry(&utx);
	}
	utx.ut_type = USER_PROCESS;
	memccpy(&(utx.ut_user), name, '\0', sizeof(utx.ut_user));
	memccpy(&(utx.ut_line), line, '\0', sizeof(utx.ut_line));
	memccpy(&(utx.ut_host), host ? host : "", '\0', sizeof(utx.ut_host));

	pututxline(&utx);
	updwtmpx(_PATH_WTMP, &utx);
}
#elif HAVE_UTMP_H
# if defined(__OpenBSD__) /* unique requirement */

void checkutmp(int picky) {
	char *line;
	struct utmp *ut;
	pid_t pid = getpid();

	setutent();

	/* First, try to find a valid utmp entry for this process.  */
	while ((ut = getutent()))
		if (ut->ut_pid == pid && ut->ut_line[0] && ut->ut_id[0] &&
		    (ut->ut_type==LOGIN_PROCESS || ut->ut_type==USER_PROCESS))
			break;

	/* If there is one, just use it, otherwise create a new one.  */
	if (ut) {
		utent = *ut;
	} else {
		if (picky) {
			puts(NO_UTENT);
			exit(1);
		}
		line = ttyname(0);
		if (!line) {
			puts(NO_TTY);
			exit(1);
		}
		if (strncmp(line, "/dev/", 5) == 0)
			line += 5;
		memset((void *) &utent, 0, sizeof utent);
		utent.ut_type = LOGIN_PROCESS;
		utent.ut_pid = pid;
		strncpy(utent.ut_line, line, sizeof utent.ut_line);
		/* XXX - assumes /dev/tty?? */
		strncpy(utent.ut_id, utent.ut_line + 3, sizeof utent.ut_id);
		strcpy(utent.ut_user, "LOGIN");
		time((time_t *) &utent.ut_time);
	}
}

/*
 * This function was used for most BSD types; however, now only
 * OpenBSD uses this.
 */
void setutmp(const char *name, const char *line, const char *host)
{
	struct	utmp	utmp;

	memset(&utmp, 0, sizeof(utmp));

	strncpy(utmp.ut_line, line, (int) sizeof utmp.ut_line);
	strncpy(utmp.ut_name, name, sizeof utent.ut_name);
	strncpy(utmp.ut_host, host, sizeof utent.ut_host);
	(void) time (&utmp.ut_time);

	login(&utmp);
	utent = utmp;
}
# else /* Other platforms should be added on a per-needs basis here */
# error "Missing utmp support for this platform"
# endif
#else /* Unable to create supported functions */
# error "This platform lacks utmp and utmpx."
#endif
