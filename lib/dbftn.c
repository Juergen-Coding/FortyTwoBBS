/*****************************************************************************
 *
 * $Id: dbftn.c,v 1.8 2005/08/28 10:03:17 mbse Exp $
 * Purpose ...............: Fidonetrecord Access
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

#include "mbselib.h"
#include "users.h"
#include "mbsedb.h"


static int valid_fidonet_header(void)
{
    return (fidonethdr.hdrsize >= (int)sizeof(fidonethdr)) &&
           (fidonethdr.recsize > 0) &&
           (fidonethdr.recsize <= (int)sizeof(fidonet));
}


static int valid_domalias_header(void)
{
    return (domaliashdr.hdrsize >= (int)sizeof(domaliashdr)) &&
           (domaliashdr.recsize > 0) &&
           (domaliashdr.recsize <= (int)sizeof(domalias));
}


int InitFidonet(void)
{
	FILE	*fil;
	long	end;

	memset(&fidonet, 0, sizeof(fidonet));
	LoadConfig();

	snprintf(fidonet_fil, PATH_MAX -1, "%s/etc/fidonet.data", getenv("MBSE_ROOT"));
	if ((fil = fopen(fidonet_fil, "r")) == NULL)
		return FALSE;

	if ((fread(&fidonethdr, sizeof(fidonethdr), 1, fil) != 1) ||
	    !valid_fidonet_header() || (fseek(fil, 0, SEEK_END) != 0) ||
	    ((end = ftell(fil)) < fidonethdr.hdrsize)) {
		fclose(fil);
		return FALSE;
	}
	fidonet_cnt = (end - fidonethdr.hdrsize) / fidonethdr.recsize;
	fclose(fil);

	return TRUE;
}



int TestFidonet(unsigned short zone)
{
	int	i, ftnok = FALSE;

	for (i = 0; i < 6; i++) {
		if (zone == fidonet.zone[i])
			ftnok = TRUE;
	}
	return(ftnok);
}



int SearchFidonet(unsigned short zone)
{
	FILE	*fil;

	/*
	 * If current record is ok, return immediately.
	 */
	if (TestFidonet(zone))
		return TRUE;

	if ((fil = fopen(fidonet_fil, "r")) == NULL) {
		return FALSE;
	}
	if ((fread(&fidonethdr, sizeof(fidonethdr), 1, fil) != 1) ||
	    !valid_fidonet_header() ||
	    (fseek(fil, fidonethdr.hdrsize, SEEK_SET) != 0)) {
		fclose(fil);
		return FALSE;
	}

	while (fread(&fidonet, (size_t)fidonethdr.recsize, 1, fil) == 1) {
		if (TestFidonet(zone)) {
			fclose(fil);
			return TRUE;
		}
	}
	fclose(fil);
	return FALSE;
}



char *GetFidoDomain(unsigned short zone)
{
    static char domain[9];

    memset(&domain, 0, sizeof(domain));

    if (SearchFidonet(zone) == FALSE)
	    return NULL;

    snprintf(domain, 9, "%.8s", fidonet.domain);
    return domain;
}


int InitDomainAlias(void)
{
        FILE	*fil;
        long	end;
        
        memset(&domalias, 0, sizeof(domalias));
        LoadConfig();
        
        snprintf(domalias_fil, PATH_MAX -1, "%s/etc/domalias.data", getenv("MBSE_ROOT"));
        if ((fil = fopen(domalias_fil, "r")) == NULL)
                return FALSE;
                
        if ((fread(&domaliashdr, sizeof(domaliashdr), 1, fil) != 1) ||
            !valid_domalias_header() || (fseek(fil, 0, SEEK_END) != 0) ||
            ((end = ftell(fil)) < domaliashdr.hdrsize)) {
                fclose(fil);
                return FALSE;
        }
        domalias_cnt = (end - domaliashdr.hdrsize) / domaliashdr.recsize;
        fclose(fil);
        
        return TRUE;
}

char *SearchDomainAlias(char *alias)
{
	FILE	*fil;

	if ((fil = fopen(domalias_fil, "r")) == NULL) {
		return NULL;
	}
	if ((fread(&domaliashdr, sizeof(domaliashdr), 1, fil) != 1) ||
	    !valid_domalias_header() ||
	    (fseek(fil, domaliashdr.hdrsize, SEEK_SET) != 0)) {
		fclose(fil);
		return NULL;
	}

	while (fread(&domalias, (size_t)domaliashdr.recsize, 1, fil) == 1) {
		if (strcmp(alias, domalias.alias) == 0) {
			fclose(fil);
			return domalias.domain;
		}
	}
	fclose(fil);
	return NULL;
}
