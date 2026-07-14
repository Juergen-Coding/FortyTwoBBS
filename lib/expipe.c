/*****************************************************************************
 *
 * $Id: expipe.c,v 1.7 2004/02/21 14:24:04 mbroek Exp $
 * Purpose ...............: MBSE BBS Execute pipe
 *
 *****************************************************************************
 * Copyright (C) 1997-2004
 *   
 * Michiel Broek		FIDO:		2:280/2802
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

#include "mbselib.h"



static struct _fppid {
    FILE    *fp;
    int	    pid;
} fppid[] = {
    {NULL, 0}, {NULL, 0}, {NULL, 0}
};

#define maxfppid 2



FILE *expipe(char *cmd, char *from, char *to)
{
    char    buf[256], *vector[16], *p, *q, *replacement, *token;
    FILE    *fp;
    size_t  remaining, length;
    int     i, pid, slot, pipedes[2], status;

    if (cmd == NULL) {
	WriteError("Expipe: missing command");
	return NULL;
    }

    for (slot = 0; slot <= maxfppid; slot++) {
	if (fppid[slot].fp == NULL)
	    break;
    }
    if (slot > maxfppid) {
	WriteError("Attempt to pipe more than %d processes", maxfppid + 1);
	return NULL;
    }

    q = buf;
    remaining = sizeof(buf);
    for (p = cmd; *p != '\0'; p++) {
	int placeholder = FALSE;

	replacement = NULL;
	if ((*p == '$') && (p[1] != '\0')) {
	    p++;
	    if ((*p == 'f') || (*p == 'F')) {
		replacement = from;
		placeholder = TRUE;
	    } else if ((*p == 't') || (*p == 'T')) {
		replacement = to;
		placeholder = TRUE;
	    } else {
		if (remaining <= 2) {
		    WriteError("Attempt to pipe too long command");
		    return NULL;
		}
		*q++ = '$';
		*q++ = *p;
		remaining -= 2;
		continue;
	    }
	} else if ((*p == '\\') && (p[1] != '\0')) {
	    p++;
	}

	if (placeholder) {
	    if (replacement == NULL)
		continue;
	    length = strlen(replacement);
	    if (length >= remaining) {
		WriteError("Attempt to pipe too long command");
		return NULL;
	    }
	    memcpy(q, replacement, length);
	    q += length;
	    remaining -= length;
	} else {
	    if (remaining <= 1) {
		WriteError("Attempt to pipe too long command");
		return NULL;
	    }
	    *q++ = *p;
	    remaining--;
	}
    }
    *q = '\0';

    memset(vector, 0, sizeof(vector));
    i = 0;
    token = strtok(buf, " \t\n");
    while ((token != NULL) && (i < 15)) {
	vector[i++] = token;
	token = strtok(NULL, " \t\n");
    }
    if ((i == 0) || (token != NULL)) {
	WriteError("Expipe: invalid or overlong argument list");
	return NULL;
    }
    vector[i] = NULL;
    Syslog('+', "Expipe program: %s", vector[0]);

    fflush(stdout);
    fflush(stderr);
    if (pipe(pipedes) != 0) {
	WriteError("$Pipe failed for command \"%s\"", MBSE_SS(vector[0]));
	return NULL;
    }

    Syslog('e', "pipe() returned read=%d, write=%d", pipedes[0], pipedes[1]);
    pid = fork();
    if (pid == -1) {
	WriteError("$Fork failed for command \"%s\"", MBSE_SS(vector[0]));
	close(pipedes[0]);
	close(pipedes[1]);
	return NULL;
    }
    if (pid == 0) {
	close(pipedes[1]);
	if (dup2(pipedes[0], STDIN_FILENO) == -1) {
	    WriteError("$Reopen of stdin for command %s failed", MBSE_SS(vector[0]));
	    close(pipedes[0]);
	    _exit(MBERR_EXEC_FAILED);
	}
	if (pipedes[0] != STDIN_FILENO)
	    close(pipedes[0]);
	execv(vector[0], vector);
	WriteError("$Exec \"%s\" failed", MBSE_SS(vector[0]));
	_exit(MBERR_EXEC_FAILED);
    }

    close(pipedes[0]);
    fp = fdopen(pipedes[1], "w");
    if (fp == NULL) {
	WriteError("$fdopen failed for pipe to command \"%s\"", MBSE_SS(vector[0]));
	close(pipedes[1]);
	do {
	    i = waitpid(pid, &status, 0);
	} while ((i == -1) && (errno == EINTR));
	return NULL;
    }

    fppid[slot].fp = fp;
    fppid[slot].pid = pid;
    return fp;
}


int exclose(FILE *fp)
{
    int	status = 0, rc, pid, slot;

    for (slot = 0; slot <= maxfppid; slot++) {
	if (fppid[slot].fp == fp) 
	    break;
    }
    if (slot > maxfppid) {
	WriteError("Attempt to close unopened pipe");
	return -1;
    }
    pid = fppid[slot].pid;
    fppid[slot].fp = NULL;
    fppid[slot].pid = 0;

    Syslog('e', "Closing pipe to the child process %d",pid);
    if ((rc = fclose(fp)) != 0) {
	WriteError("$Error closing pipe to transport (rc=%d)", rc);
	if ((rc = kill(pid,SIGKILL)) != 0)
	    WriteError("$kill for pid %d returned %d",pid,rc);
    }
    Syslog('e', "Waiting for process %d to finish",pid);
    do {
	rc = waitpid(pid, &status, 0);
    } while ((rc == -1) && (errno == EINTR));
    if ((rc > 0) && status)
	Syslog('e', "Wait returned %d, status %d,%d", rc, status >> 8, status & 0xff);

    switch (rc) {
	case -1:WriteError("$Wait returned %d, status %d,%d", rc, status >> 8, status & 0xff);
		return MBERR_EXEC_FAILED;
	case 0:	return 0;
	default:
		if (WIFEXITED(status)) {
		    rc = WEXITSTATUS(status);
		    if (rc) {
			WriteError("Expipe: returned error %d", rc);
			return (rc + MBERR_EXTERNAL);
		    }
		}
		if (WIFSIGNALED(status)) {
		    rc = WTERMSIG(status);
		    WriteError("Wait stopped on signal %d", rc);
		    return rc;
		}
		if (rc)
		    WriteError("Wait stopped unknown, rc=%d", rc);
		return rc;
    }
    return 0;
}

