/*****************************************************************************
 *
 * $Id: auth.c,v 1.5 2005/09/07 20:44:37 mbse Exp $
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

#include "../lib/mbselib.h"
#include "../lib/users.h"
#include "mbnntp.h"
#include "auth.h"

#ifndef	USE_NEWSGATE

int	authorized = FALSE;	    /* Authentication status	*/
int	got_username = FALSE;	    /* Did we get a username?	*/
int	grecno = 0;		    /* User record number	*/
char	username[9];		    /* Cached username		*/

extern pid_t	mypid;


int check_auth(char *cmd)
{
    if (authorized)
	return TRUE;

    send_nntp("480 Authentication required");
    return FALSE;
}



void auth_user(char *cmd)
{
    char    *p;

    got_username = FALSE;
    memset(username, 0, sizeof(username));
    if (cmd == NULL) {
	WriteError("Malformed AUTHINFO USER command");
	send_nntp("482 Authentication rejected");
	return;
    }

    p = strtok(cmd, " \0");
    if (p != NULL)
	p = strtok(NULL, " \0");
    if (p != NULL)
	p = strtok(NULL, " \0");
    if ((p == NULL) || (*p == '\0')) {
	WriteError("AUTHINFO USER without username");
	send_nntp("482 Authentication rejected");
	return;
    }
    if (strlen(p) >= sizeof(username)) {
	WriteError("Got a username of %u characters", (unsigned int)strlen(p));
	send_nntp("482 Authentication rejected");
	return;
    }

    snprintf(username, sizeof(username), "%s", p);
    send_nntp("381 More authentication information required");
    got_username = TRUE;
}


void auth_pass(char *cmd)
{
    char    *p, path[PATH_MAX];
    const char *root;
    FILE    *fp;
    int     FoundName = FALSE;

    if (!got_username) {
	WriteError("Got AUTHINFO PASS before AUTHINFO USER");
	send_nntp("482 Authentication rejected");
	return;
    }

    if (cmd == NULL) {
	WriteError("Malformed AUTHINFO PASS command");
	send_nntp("482 Authentication rejected");
	got_username = FALSE;
	return;
    }
    p = strtok(cmd, " \0");
    if (p != NULL)
	p = strtok(NULL, " \0");
    if (p != NULL)
	p = strtok(NULL, " \0");
    if (p == NULL) {
	WriteError("AUTHINFO PASS without password");
	send_nntp("482 Authentication rejected");
	got_username = FALSE;
	return;
    }

    root = getenv("MBSE_ROOT");
    if ((root == NULL) || (*root == '\0') ||
	(snprintf(path, sizeof(path), "%s/etc/users.data", root) >= (int)sizeof(path))) {
	WriteError("Invalid MBSE_ROOT while authenticating NNTP user");
	send_nntp("482 Authentication rejected");
	got_username = FALSE;
	return;
    }
    if ((fp = fopen(path, "r+")) == NULL) {
	WriteError("$Can't open %s", path);
	send_nntp("482 Authentication rejected");
	got_username = FALSE;
	return;
    }

    if ((fread(&usrconfighdr, sizeof(usrconfighdr), 1, fp) != 1) ||
	(usrconfighdr.recsize <= 0) ||
	((size_t)usrconfighdr.recsize > sizeof(usrconfig)) ||
	(usrconfighdr.hdrsize < (int)sizeof(usrconfighdr)) ||
	(fseek(fp, usrconfighdr.hdrsize, SEEK_SET) != 0)) {
	WriteError("Invalid users.data header");
	send_nntp("482 Authentication rejected");
	fclose(fp);
	got_username = FALSE;
	return;
    }

    grecno = 0;
    while (TRUE) {
	memset(&usrconfig, 0, sizeof(usrconfig));
	if (fread(&usrconfig, usrconfighdr.recsize, 1, fp) != 1)
	    break;
	usrconfig.Name[sizeof(usrconfig.Name) - 1] = '\0';
	usrconfig.Password[sizeof(usrconfig.Password) - 1] = '\0';
	if (strcmp(usrconfig.Name, username) == 0) {
	    FoundName = TRUE;
	    usercharset = usrconfig.Charset;
	    break;
	}
	grecno++;
    }

    if (!FoundName) {
	fclose(fp);
	Syslog('+', "Unknown user \"%s\", reject", username);
	send_nntp("482 Authentication rejected");
	got_username = FALSE;
	memset(&usrconfig, 0, sizeof(usrconfig));
	return;
    }

    if (usrconfig.Deleted || usrconfig.LockedOut) {
	Syslog('+', "Disabled NNTP account rejected for user \"%s\"", username);
	send_nntp("482 Authentication rejected");
	fclose(fp);
	got_username = FALSE;
	memset(&usrconfig, 0, sizeof(usrconfig));
	return;
    }

    /* Legacy compatibility only: users.data still stores a cleartext password. */
    if (strcmp(usrconfig.Password, p) != 0) {
	Syslog('+', "Password error, reject user \"%s\"", username);
	send_nntp("482 Authentication rejected");
	fclose(fp);
	got_username = FALSE;
	memset(&usrconfig, 0, sizeof(usrconfig));
	return;
    }

    usrconfig.tLastLoginDate = time(NULL);
    usrconfig.iTotalCalls++;

    if ((fseek(fp, usrconfighdr.hdrsize +
	      ((long)grecno * usrconfighdr.recsize), SEEK_SET) != 0) ||
	(fwrite(&usrconfig, usrconfighdr.recsize, 1, fp) != 1)) {
	WriteError("Can't update %s", path);
	send_nntp("482 Authentication rejected");
	fclose(fp);
	got_username = FALSE;
	memset(&usrconfig, 0, sizeof(usrconfig));
	return;
    }
    fclose(fp);

    if (strlen(usrconfig.sLocation))
	UserCity(mypid, usrconfig.Name, usrconfig.sLocation);
    else
	UserCity(mypid, usrconfig.Name, (char *)"N/A");

    IsDoing("Logged in");
    Syslog('+', "User %s logged in", username);
    authorized = TRUE;
    got_username = FALSE;
    send_nntp("281 Authentication accepted");
}

#endif
