/*****************************************************************************
 *
 * $Id: exitinfo.c,v 1.15 2005/10/11 20:49:48 mbse Exp $
 * Purpose ...............: Exitinfo functions
 *
 *****************************************************************************
 * Copyright (C) 1997-2005
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
#include "funcs.h"
#include "input.h"
#include "language.h"
#include "oneline.h"
#include "misc.h"
#include "bye.h"
#include "timeout.h"
#include "timecheck.h"
#include "exitinfo.h"
#include "fortytwo_session.h"



/*
 * Copy the selected users.data record into this session's private state file.
 * The file is keyed by the authenticated session UUID, not by the legacy user
 * name, so a later multi-session implementation cannot overwrite another
 * process's in-memory snapshot.
 */
int InitExitinfo()
{
    FILE        *pUsrConfig, *pExitinfo;
    const char  *state_path;
    char        *temp;
    int         offset;

    state_path = FortyTwoSessionExitinfoPath();
    if (state_path == NULL) {
        WriteError("$FortyTwo session state is not prepared");
        return FALSE;
    }

    temp = calloc(PATH_MAX, sizeof(char));
    snprintf(temp, PATH_MAX, "%s/etc/users.data", getenv("MBSE_ROOT"));

    if ((pUsrConfig = fopen(temp, "r+b")) == NULL) {
        WriteError("$Can't open %s for writing", temp);
        free(temp);
        return FALSE;
    }

    if (fread(&usrconfighdr, sizeof(usrconfighdr), 1, pUsrConfig) != 1) {
        WriteError("$Can't read user header from %s", temp);
        fclose(pUsrConfig);
        free(temp);
        return FALSE;
    }
    offset = usrconfighdr.hdrsize + (grecno * usrconfighdr.recsize);
    if (fseek(pUsrConfig, offset, SEEK_SET) != 0) {
        WriteError("$Can't move pointer in %s", temp);
        fclose(pUsrConfig);
        free(temp);
        return FALSE;
    }
    if (fread(&usrconfig, usrconfighdr.recsize, 1, pUsrConfig) != 1) {
        WriteError("$Can't read user record from %s", temp);
        fclose(pUsrConfig);
        free(temp);
        return FALSE;
    }

    exitinfo = usrconfig;
    fclose(pUsrConfig);

    if ((pExitinfo = fopen(state_path, "w+b")) == NULL) {
        WriteError("$Can't open %s for writing", state_path);
        free(temp);
        return FALSE;
    }
    if (fwrite(&exitinfo, sizeof(exitinfo), 1, pExitinfo) != 1) {
        WriteError("$Can't write %s", state_path);
        fclose(pExitinfo);
        free(temp);
        return FALSE;
    }
    fclose(pExitinfo);
    if (chmod(state_path, 0600))
        WriteError("$Can't chmod 0600 %s", state_path);

    free(temp);
    return TRUE;
}


/* Re-read only this process's session snapshot. */
void ReadExitinfo()
{
    FILE        *pExitinfo;
    const char  *state_path;

    state_path = FortyTwoSessionExitinfoPath();
    if (state_path == NULL) {
        WriteError("$FortyTwo session state is not prepared");
        return;
    }

    if ((pExitinfo = fopen(state_path, "r+b")) == NULL) {
        if (!InitExitinfo())
            WriteError("$Can't initialize %s", state_path);
        return;
    }
    if (fread(&exitinfo, sizeof(exitinfo), 1, pExitinfo) != 1)
        WriteError("$Can't read %s", state_path);
    fclose(pExitinfo);
}


/* Rewrite only this process's session snapshot. */
void WriteExitinfo()
{
    FILE        *pExitinfo;
    const char  *state_path;

    state_path = FortyTwoSessionExitinfoPath();
    if (state_path == NULL) {
        WriteError("$FortyTwo session state is not prepared");
        return;
    }

    if ((pExitinfo = fopen(state_path, "w+b")) == NULL) {
        WriteError("$WriteExitinfo() failed for %s", state_path);
        return;
    }
    if (fwrite(&exitinfo, sizeof(exitinfo), 1, pExitinfo) != 1)
        WriteError("$Can't write %s", state_path);
    fclose(pExitinfo);
}
