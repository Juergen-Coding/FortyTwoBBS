/*****************************************************************************
 *
 * $Id: execute.c,v 1.24 2008/02/23 21:50:41 mbse Exp $
 * Purpose ...............: Execute subprogram
 *
 *****************************************************************************
 * Copyright (C) 1997-2005
 *   
 * Michiel Broek		FIDO:	2:280/2802
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


int	e_pid = 0;		/* Execute child pid	*/


int _execute(char **, char *, char *, char *);
int _execute(char **args, char *in, char *out, char *err)
{
    int     pid, status = 0, rc, fd;

    if ((args == NULL) || (args[0] == NULL) || (args[0][0] == '\0')) {
	WriteError("Execute: missing program name");
	return -1;
    }

    /* Arguments can contain credentials; never copy the full argv to logs. */
    Syslog('+', "Execute program: %s", args[0]);
    fflush(stdout);
    fflush(stderr);

    pid = fork();
    if (pid == -1) {
	WriteError("$Execute: fork failed");
	return -1;
    }
    if (pid == 0) {
	/*
	 * A delay in the child to prevent it returning before the main
	 * process sees it ever started.
	 */
	msleep(150);

	if (in != NULL) {
	    fd = open(in, O_RDONLY);
	    if ((fd == -1) || ((fd != STDIN_FILENO) &&
		(dup2(fd, STDIN_FILENO) == -1))) {
		WriteError("$Reopen of stdin to %s failed", MBSE_SS(in));
		if (fd >= 0)
		    close(fd);
		_exit(MBERR_EXEC_FAILED);
	    }
	    if (fd != STDIN_FILENO)
		close(fd);
	}
	if (out != NULL) {
	    fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0600);
	    if ((fd == -1) || ((fd != STDOUT_FILENO) &&
		(dup2(fd, STDOUT_FILENO) == -1))) {
		WriteError("$Reopen of stdout to %s failed", MBSE_SS(out));
		if (fd >= 0)
		    close(fd);
		_exit(MBERR_EXEC_FAILED);
	    }
	    if (fd != STDOUT_FILENO)
		close(fd);
	}
	if (err != NULL) {
	    fd = open(err, O_WRONLY | O_APPEND | O_CREAT, 0600);
	    if ((fd == -1) || ((fd != STDERR_FILENO) &&
		(dup2(fd, STDERR_FILENO) == -1))) {
		WriteError("$Reopen of stderr to %s failed", MBSE_SS(err));
		if (fd >= 0)
		    close(fd);
		_exit(MBERR_EXEC_FAILED);
	    }
	    if (fd != STDERR_FILENO)
		close(fd);
	}

	errno = 0;
	if (CFG.priority) {
	    rc = getpriority(PRIO_PROCESS, 0);
	    if (errno == 0) {
		rc = setpriority(PRIO_PROCESS, 0, CFG.priority);
		if (rc)
		    WriteError("$execv can't set priority to %d", CFG.priority);
	    }
	}
	execv(args[0], args);
	WriteError("$execv \"%s\" failed", MBSE_SS(args[0]));
	_exit(MBERR_EXEC_FAILED);
    }

    e_pid = pid;
    do {
	rc = waitpid(pid, &status, 0);
    } while ((rc == -1) && (errno == EINTR));
    e_pid = 0;

    if (rc == -1) {
	if (errno == ECHILD) {
	    Syslog('+', "Execute: no child process");
	    return 0;
	}
	WriteError("$waitpid failed");
	return -1;
    }
    if (WIFEXITED(status)) {
	rc = WEXITSTATUS(status);
	if (rc != 0) {
	    if ((strstr(args[0], (char *)"unzip") == NULL) || (rc != 11))
		WriteError("Execute: returned error %d", rc);
	    return rc + MBERR_EXTERNAL;
	}
	return 0;
    }
    if (WIFSIGNALED(status)) {
	rc = WTERMSIG(status);
	WriteError("Wait stopped on signal %d", rc);
	return rc;
    }

    WriteError("Wait stopped in an unexpected state");
    return -1;
}


int execute(char **args, char *in, char *out, char *err)
{
    int	    rc;

    if (CFG.do_sync)
	sync();
    rc = _execute(args, in, out, err);
    if (CFG.do_sync)
	sync();
    return rc;
}



/*
 * The old behaviour, parse command strings to arguments.
 */
int execute_str(char *cmd, char *fil, char *pkt, char *in, char *out, char *err)
{
    int     i = 0, written;
    char    *args[16], *token, buf[PATH_MAX];

    if ((cmd == NULL) || (*cmd == '\0') || (fil == NULL)) {
	WriteError("execute_str: invalid command or filename");
	return -1;
    }

    memset(args, 0, sizeof(args));
    memset(buf, 0, sizeof(buf));
    if ((pkt != NULL) && strlen(pkt))
	written = snprintf(buf, sizeof(buf), "%s %s %s", cmd, fil, pkt);
    else
	written = snprintf(buf, sizeof(buf), "%s %s", cmd, fil);
    if ((written < 0) || (written >= (int)sizeof(buf))) {
	WriteError("execute_str: command line is too long");
	return -1;
    }

    token = strtok(buf, " \t\n");
    while ((token != NULL) && (i < 15)) {
	args[i++] = token;
	token = strtok(NULL, " \t\n");
    }
    if (token != NULL) {
	WriteError("execute_str: too many command arguments");
	return -1;
    }
    args[i] = NULL;
    if (i == 0)
	return -1;

    return execute(args, in, out, err);
}


/*
 * Execute command in the PATH.
 */
int execute_pth(char *prog, char *opts, char *in, char *out, char *err)
{
    char    *pth;
    int	    rc;

    if ((prog == NULL) || (*prog == '\0') || strchr(prog, ' ') || strchr(prog, '/')) {
	WriteError("First parameter of execute_pth() must be a program name");
	return -1;
    }

    pth = xstrcpy((char *)"/usr/bin/");
    pth = xstrcat(pth, prog);
    if (access(pth, X_OK) == -1) {
	free(pth);
	pth = xstrcpy((char *)"/usr/local/bin/");
	pth = xstrcat(pth, prog);
	if (access(pth, X_OK) == -1) {
	    free(pth);
	    pth = xstrcpy((char *)"/bin/");
	    pth = xstrcat(pth, prog);
	    if (access(pth, X_OK) == -1) {
		free(pth);
		pth = xstrcpy((char *)"/usr/pkg/bin/");
		pth = xstrcat(pth, prog);
		if (access(pth, X_OK) == -1) {
		    WriteError("Can't find %s", prog);
		    free(pth);
		    return -1;
		}
	    }
	}
    }

    rc = execute_str(pth, opts, NULL, in, out, err);
    free(pth);
    return rc;
}



#define SHELL "/bin/sh"


int _execsh(char *, char *, char *, char *);
int _execsh(char *cmd, char *in, char *out, char *err)
{
    int pid, status = 0, rc, fd;

    if ((cmd == NULL) || (*cmd == '\0')) {
	WriteError("Execute shell: missing command");
	return -1;
    }
    /* Shell command strings can contain credentials; do not log them. */
    Syslog('+', "Execute shell command");
    fflush(stdout);
    fflush(stderr);

    pid = fork();
    if (pid == -1) {
	WriteError("$Execute shell: fork failed");
	return -1;
    }
    if (pid == 0) {
	msleep(150);

	if (in != NULL) {
	    fd = open(in, O_RDONLY);
	    if ((fd == -1) || ((fd != STDIN_FILENO) &&
		(dup2(fd, STDIN_FILENO) == -1))) {
		WriteError("$Reopen of stdin to %s failed", MBSE_SS(in));
		if (fd >= 0)
		    close(fd);
		_exit(MBERR_EXEC_FAILED);
	    }
	    if (fd != STDIN_FILENO)
		close(fd);
	}
	if (out != NULL) {
	    fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0600);
	    if ((fd == -1) || ((fd != STDOUT_FILENO) &&
		(dup2(fd, STDOUT_FILENO) == -1))) {
		WriteError("$Reopen of stdout to %s failed", MBSE_SS(out));
		if (fd >= 0)
		    close(fd);
		_exit(MBERR_EXEC_FAILED);
	    }
	    if (fd != STDOUT_FILENO)
		close(fd);
	}
	if (err != NULL) {
	    fd = open(err, O_WRONLY | O_APPEND | O_CREAT, 0600);
	    if ((fd == -1) || ((fd != STDERR_FILENO) &&
		(dup2(fd, STDERR_FILENO) == -1))) {
		WriteError("$Reopen of stderr to %s failed", MBSE_SS(err));
		if (fd >= 0)
		    close(fd);
		_exit(MBERR_EXEC_FAILED);
	    }
	    if (fd != STDERR_FILENO)
		close(fd);
	}

	execl(SHELL, "sh", "-c", cmd, NULL);
	WriteError("$execl shell command failed");
	_exit(MBERR_EXEC_FAILED);
    }

    e_pid = pid;
    do {
	rc = waitpid(pid, &status, 0);
    } while ((rc == -1) && (errno == EINTR));
    e_pid = 0;

    if (rc == -1) {
	WriteError("$waitpid for shell command failed");
	return -1;
    }
    if (WIFEXITED(status)) {
	rc = WEXITSTATUS(status);
	return rc == 0 ? 0 : rc + MBERR_EXTERNAL;
    }
    if (WIFSIGNALED(status)) {
	rc = WTERMSIG(status);
	WriteError("Shell command stopped on signal %d", rc);
	return rc;
    }
    WriteError("Shell command stopped in an unexpected state");
    return -1;
}

int execsh(char *cmd, char *in, char *out, char *err)
{
    int	rc;

    if (CFG.do_sync)
	sync();
    rc = _execsh(cmd, in, out, err);
    if (CFG.do_sync)
	sync();
    return rc;
}

