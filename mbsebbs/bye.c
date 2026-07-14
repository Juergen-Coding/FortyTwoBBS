/*****************************************************************************
 *
 * $Id: bye.c,v 1.32 2008/02/12 19:59:45 mbse Exp $
 * Purpose ...............: Hangup functions
 *
 *****************************************************************************
 * Copyright (C) 1997-2006
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

#include "../lib/mbselib.h"
#include "../lib/mbse.h"
#include "../lib/users.h"
#include "../lib/nodelist.h"
#include "dispfile.h"
#include "misc.h"
#include "language.h"
#include "bye.h"
#include "term.h"
#include "openport.h"
#include "ttyio.h"
#include "mib.h"
#include "fortytwo_session.h"


extern	pid_t		mypid;
extern	time_t		t_start;
extern	char		*StartTime;
extern	int		hanged_up;

extern	unsigned int	mib_sessions;
extern	unsigned int	mib_minutes;


int			do_mailout = FALSE;


/* Keep database session-end reasons stable and machine-readable. */
static const char *
FortyTwoEndReason(int onsig)
{
    if (onsig == 0 || onsig == MBERR_OK)
        return "normal_logout";
    if (onsig == SIGALRM || onsig == MBERR_TIMEOUT)
        return "idle_timeout";
    if (onsig == SIGHUP)
        return "carrier_lost";
    if (onsig == SIGPIPE)
        return "transport_error";
    if (onsig > 0 && onsig <= NSIG)
        return "signal_terminated";
    return "bbs_error";
}


void Good_Bye(int onsig)
{
    FILE    *pUsrConfig, *pExitinfo;
    char    *temp;
    const char *state_path;
    int	    offset;
    time_t  t_end;
    int	    i;

    IsDoing("Hangup");
    temp = calloc(PATH_MAX, sizeof(char));
    Syslog('+', "Good_Bye(%d)", onsig);

    /*
     * Don't display goodbye screen on SIGHUP and idle timeout.
     * With idle timeout this will go into a loop.
     */
    if ((onsig != SIGALRM) && (onsig != MBERR_TIMEOUT) && (hanged_up == 0))
	DisplayFile((char *)"goodbye");

    SaveLastCallers();

    /*
     * Commit this session's private exitinfo snapshot back to the selected
     * users.data record while the per-user lock is still held.
     */
    if (!usrconfig.Guest) {
        snprintf(temp, PATH_MAX, "%s/etc/users.data", getenv("MBSE_ROOT"));
        pUsrConfig = fopen(temp, "r+");
        state_path = FortyTwoSessionExitinfoPath();
        pExitinfo = state_path != NULL ? fopen(state_path, "rb") : NULL;

        if (pUsrConfig == NULL) {
            WriteError("$Can't open %s for updating", temp);
        } else if (pExitinfo == NULL) {
            WriteError("$Can't open private session state");
        } else if (fread(&usrconfighdr, sizeof(usrconfighdr), 1,
                         pUsrConfig) != 1 ||
                   fread(&exitinfo, sizeof(exitinfo), 1, pExitinfo) != 1) {
            WriteError("$Can't read user logout state");
        } else {
            usrconfig = exitinfo;
            usrconfig.iLastFileArea = iAreaNumber;
            usrconfig.iLastMsgArea = iMsgAreaNumber;

            if (!iExpired && !hanged_up)
                Syslog('+', "User successfully logged off BBS");

            offset = usrconfighdr.hdrsize + (grecno * usrconfighdr.recsize);
            if (fseek(pUsrConfig, offset, SEEK_SET) != 0) {
                WriteError("$Can't move pointer in file %s/etc/users.data",
                           getenv("MBSE_ROOT"));
            } else if (fwrite(&usrconfig, sizeof(usrconfig), 1,
                              pUsrConfig) != 1) {
                WriteError("$Can't update %s/etc/users.data",
                           getenv("MBSE_ROOT"));
            }
        }

        if (pExitinfo != NULL)
            fclose(pExitinfo);
        if (pUsrConfig != NULL)
            fclose(pUsrConfig);
    } else {
        if (!iExpired && !hanged_up)
            Syslog('+', "Guest account successfully logged off BBS");
    }

    /*
     * Update mib counters
     */
    t_end = time(NULL);
    mib_minutes = (unsigned int) ((t_end - t_start) / 60);
    mib_sessions++;

    sendmibs();

    /*
     * Flush all data to the user, wait 5 seconds to
     * be sure the user received all data.
     */
    if ((onsig != SIGALRM) && (onsig != MBERR_TIMEOUT) && (hanged_up == 0)) {
	colour(LIGHTGRAY, BLACK);
	sleep(4);
    }

    for (i = 0; i < NSIG; i++) {
	if (i == SIGCHLD)
	    signal(i, SIG_DFL);
	else if ((i != SIGKILL) && (i != SIGSTOP))
	    signal(i, SIG_DFL);
    }

    if ((onsig != SIGALRM) && (onsig != MBERR_TIMEOUT) && (hanged_up == 0)) {
    	cookedport();
    }

    /*
     * Ignore SIGHUP during hangup.
     */
    signal(SIGHUP, SIG_IGN);
    hangup();

    for (i = 0; i < NSIG; i++) {
	if ((i == SIGHUP) || (i == SIGPIPE) || (i == SIGBUS) || (i == SIGILL) || (i == SIGSEGV) || (i == SIGTERM))
	    signal(i, SIG_DFL);
    }
    
    if (do_mailout)
	CreateSema((char *)"mailout");

    t_end = time(NULL);
    Syslog(' ', "MBSEBBS finished in %s", t_elapsed(t_start, t_end));
    sleep(1);

    /*
     * Start shutting down this session, cleanup some files.
     */
    socket_shutdown(mypid);
    snprintf(temp, PATH_MAX, "%s/tmp/mbsebbs%d", getenv("MBSE_ROOT"), getpid());
    unlink(temp);

    snprintf(temp, PATH_MAX, "%s/%s/.quote", CFG.bbs_usersdir, exitinfo.Name);
    unlink(temp);

    snprintf(temp, PATH_MAX, "%s/%s/data.msg", CFG.bbs_usersdir, exitinfo.Name);
    unlink(temp);

    snprintf(temp, PATH_MAX, "%s/%s/door.sys", CFG.bbs_usersdir, exitinfo.Name);
    unlink(temp);

    snprintf(temp, PATH_MAX, "%s/%s/door32.sys", CFG.bbs_usersdir, exitinfo.Name);
    unlink(temp);
    
    snprintf(temp, PATH_MAX, "%s/%s/dorinfo1.def", CFG.bbs_usersdir, exitinfo.Name);
    unlink(temp);

    free(temp);
    unlink("taglist");

    Free_Language();
    free(pTTY);
    if (StartTime)
	free(StartTime);
    deinitnl();
    FortyTwoSessionClose(FortyTwoEndReason(onsig));
    exit(onsig);
}



void Quick_Bye(int onsig)
{
    char    *temp;
    int	    i;

    temp = calloc(PATH_MAX, sizeof(char));
    Syslog('+', "Quick_Bye");
    socket_shutdown(mypid);
    snprintf(temp, PATH_MAX, "%s/tmp/mbsebbs%d", getenv("MBSE_ROOT"), getpid());
    unlink(temp);
    free(temp);
    colour(LIGHTGRAY, BLACK);
    sleep(3);

    if ((onsig != SIGALRM) && (onsig != MBERR_TIMEOUT) && (hanged_up == 0)) {
        cookedport();
    }

    /*
     * Ignore SIGHUP during hangup
     */
    signal(SIGHUP, SIG_IGN);
    hangup();

    /*
     * Prevent that we call die() if something goes wrong next
     */
    for (i = 0; i < NSIG; i++)
        if ((i == SIGHUP) || (i == SIGPIPE) || (i == SIGBUS) || (i == SIGILL) || (i == SIGSEGV) || (i == SIGTERM))
            signal(i, SIG_DFL);

    free(pTTY);
    if (StartTime)
	free(StartTime);
    FortyTwoSessionClose("startup_failed");
    exit(MBERR_OK);
}



