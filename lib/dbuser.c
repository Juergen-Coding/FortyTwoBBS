/*****************************************************************************
 *
 * $Id: dbuser.c,v 1.8 2005/08/28 10:03:17 mbse Exp $
 * Purpose ...............: Userrecord Access
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
#include "users.h"
#include "mbsedb.h"


static int valid_user_header(void)
{
    return (usrhdr.hdrsize >= (int)sizeof(usrhdr)) &&
           (usrhdr.recsize > 0) &&
           (usrhdr.recsize <= (int)sizeof(usr));
}


int InitUser(void)
{
	FILE	*fil;
	long	end;

	memset(&usr, 0, sizeof(usr));
	LoadConfig();

	snprintf(usr_fil, PATH_MAX -1, "%s/etc/users.data", getenv("MBSE_ROOT"));
	if ((fil = fopen(usr_fil, "r")) == NULL)
		return FALSE;

	if ((fread(&usrhdr, sizeof(usrhdr), 1, fil) != 1) ||
	    !valid_user_header() || (fseek(fil, 0, SEEK_END) != 0) ||
	    ((end = ftell(fil)) < usrhdr.hdrsize)) {
		fclose(fil);
		return FALSE;
	}
	usr_cnt = (end - usrhdr.hdrsize) / usrhdr.recsize;
	fclose(fil);

	return TRUE;
}



int TestUser(char *Name)
{
	int	userok = FALSE;

	if (Name == NULL)
		return FALSE;
	if ((strcasecmp(usr.sUserName, Name) == 0) ||
	    ((strlen(usr.sHandle) > 0) && (strcasecmp(usr.sHandle, Name) == 0)) ||
	    (strcmp(usr.Name, Name) == 0)) {
		if (!usr.Deleted)
			userok = TRUE;
	}
	return(userok);
}



int SearchUser(char *Name)
{
	FILE	*fil;

	/*
	 * Allways reread the users file.
	 */
	if ((fil = fopen(usr_fil, "r")) == NULL) {
		memset(&usr, 0, sizeof(usr));
		return FALSE;
	}
	if ((fread(&usrhdr, sizeof(usrhdr), 1, fil) != 1) ||
	    !valid_user_header() ||
	    (fseek(fil, usrhdr.hdrsize, SEEK_SET) != 0)) {
		fclose(fil);
		return FALSE;
	}

	while (fread(&usr, (size_t)usrhdr.recsize, 1, fil) == 1) {
		if (TestUser(Name)) {
			fclose(fil);
			return TRUE;
		}
	}
	fclose(fil);
	return FALSE;
}



