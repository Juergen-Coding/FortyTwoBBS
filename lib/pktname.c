/*****************************************************************************
 *
 * $Id: pktname.c,v 1.16 2007/02/03 12:18:42 mbse Exp $
 * Purpose ...............: BinkleyTerm outbound naming
 *
 *****************************************************************************
 * Copyright (C) 1997-2007
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
#include "users.h"
#include "mbsedb.h"


#ifndef PATH_MAX
#define PATH_MAX 512
#endif

#define ptyp "ut"
#define ftyp "lo"
#define ttyp "pk"
#define rtyp "req"
#define styp "spl"
#define btyp "bsy"
#define qtyp "sts"
#define ltyp "pol"



char *prepbuf(faddr *);
char *prepbuf(faddr *addr)
{
    static char buf[PATH_MAX];
    char        *p, *domain = NULL, zpref[8];
    const char  *domain_name;
    size_t      remaining, used;
    int         i;

    buf[0] = '\0';
    zpref[0] = '\0';

    if (addr == NULL) {
        WriteError("prepbuf: NULL address");
        return buf;
    }

    snprintf(buf, sizeof(buf), "%s", CFG.outbound);

    if (CFG.addr4d) {
        Syslog('o', "Use 4d addressing, zone is %d", addr->zone);

        if ((addr->zone == 0) || (addr->zone == CFG.aka[0].zone))
            zpref[0] = '\0';
        else
            snprintf(zpref, sizeof(zpref), ".%03x", addr->zone & 0xfff);
    } else {
        /*
         * If we got a 5d address we use the given domain, if
         * we got a 4d address, we look for a matching domain name.
         */
        domain_name = ((addr->domain != NULL) && (*addr->domain != '\0')) ?
                      addr->domain : GetFidoDomain(addr->zone);
        if ((domain_name != NULL) && (*domain_name != '\0'))
            domain = xstrcpy((char *)domain_name);

        /*
         * If we got a 2d address, add the default zone.
         */
        if (addr->zone == 0)
            addr->zone = CFG.aka[0].zone;

        if ((domain != NULL) && (CFG.aka[0].domain[0] != '\0') &&
            (strcasecmp(domain, CFG.aka[0].domain) != 0)) {
            p = strrchr(buf, '/');
            p = (p != NULL) ? p + 1 : buf;
            remaining = sizeof(buf) - (size_t)(p - buf);
            snprintf(p, remaining, "%s", domain);
            for (; *p != '\0'; p++)
                *p = (char)tolower((unsigned char)*p);

            for (i = 0; i < 40; i++) {
                if ((CFG.aka[i].domain[0] != '\0') &&
                    (strcasecmp(CFG.aka[i].domain, domain) == 0))
                    break;
            }

            /*
             * Only a matching configured AKA can make this the
             * default zone.  Never dereference CFG.aka[40].
             */
            if ((i < 40) && (CFG.aka[i].zone == addr->zone))
                zpref[0] = '\0';
            else
                snprintf(zpref, sizeof(zpref), ".%03x", addr->zone & 0xfff);
        } else {
            if (addr->zone == CFG.aka[0].zone)
                zpref[0] = '\0';
            else
                snprintf(zpref, sizeof(zpref), ".%03x", addr->zone & 0xfff);
        }
    }

    used = strlen(buf);
    if (used < sizeof(buf)) {
        if (addr->point)
            snprintf(buf + used, sizeof(buf) - used, "%s/%04x%04x.pnt/%08x.",
                     zpref, addr->net, addr->node, addr->point);
        else
            snprintf(buf + used, sizeof(buf) - used, "%s/%04x%04x.",
                     zpref, addr->net, addr->node);
    }

    free(domain);
    return buf;
}


static void append_suffix(char *buffer, const char *format, ...)
{
    size_t  used;
    va_list ap;

    if ((buffer == NULL) || (format == NULL))
        return;

    used = strnlen(buffer, PATH_MAX);
    if (used >= PATH_MAX) {
        buffer[PATH_MAX - 1] = '\0';
        return;
    }

    va_start(ap, format);
    vsnprintf(buffer + used, PATH_MAX - used, format, ap);
    va_end(ap);
}


char *pktname(faddr *addr, char flavor)
{
    static char	*p, *q;

    p = prepbuf(addr);
    if (flavor == 'f') 
	flavor = 'o';
    if (flavor == 'i')
	flavor = 'd';

    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%c%s", flavor, ptyp);
    return p;
}



char *floname(faddr *addr, char flavor)
{
    static char	*p, *q;

    p = prepbuf(addr);
    if (flavor == 'o') 
	flavor = 'f';
    if (flavor == 'i')
	flavor = 'd';

    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%c%s", flavor, ftyp);
    return p;
}



char *reqname(faddr *addr)
{
    static char *p, *q;

    p = prepbuf(addr);
    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%s", rtyp);
    return p;
}



char *splname(faddr *addr)
{
    static char *p, *q;

    p = prepbuf(addr);
    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%s", styp);
    return p;
}



char *bsyname(faddr *addr)
{
    static char	*p, *q;

    p = prepbuf(addr);
    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%s", btyp);
    return p;
}



char *stsname(faddr *addr)
{
    static char *p, *q;

    p = prepbuf(addr);
    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%s", qtyp);
    return p;
}



char *polname(faddr *addr)
{
    static char	*p, *q;

    p = prepbuf(addr);
    q = p + strlen(p);
    (void)q;
    append_suffix(p, "%s", ltyp);
    return p;
}



static char *dow[] = {(char *)"su", (char *)"mo", (char *)"tu", (char *)"we", 
		      (char *)"th", (char *)"fr", (char *)"sa"};

char *dayname(void)
{
    time_t	tt;
    struct	tm *ptm;
    static char	buf[3];
    
    tt = time(NULL);
    ptm = localtime(&tt);
    if (ptm == NULL)
        snprintf(buf, sizeof(buf), "??");
    else
        snprintf(buf, sizeof(buf), "%s", dow[ptm->tm_wday]);

    return buf;	
}



char *arcname(faddr *addr, unsigned short Zone, int ARCmailCompat)
{
    static char *buf;
    char        *p;
    const char  *ext;
    time_t      tt;
    struct tm   *ptm;
    faddr       *bestaka;
    size_t      remaining;

    if (addr == NULL)
        return prepbuf(NULL);

    tt = time(NULL);
    ptm = localtime(&tt);
    ext = (ptm != NULL) ? dow[ptm->tm_wday] : "??";

    bestaka = bestaka_s(addr);
    buf = prepbuf(addr);
    p = strrchr(buf, '/');
    if (p == NULL)
        p = buf + strlen(buf);
    remaining = PATH_MAX - (size_t)(p - buf);

    if (!ARCmailCompat && (Zone != addr->zone)) {
        snprintf(p, remaining, "/%08x.%s0",
                 StringCRC32(ascfnode(addr, 0x1f)), ext);
    } else if (bestaka != NULL) {
        if (addr->point) {
            snprintf(p, remaining, "/%04x%04x.%s0",
                     ((bestaka->net) - (addr->net)) & 0xffff,
                     ((bestaka->node) - (addr->node) + (addr->point)) & 0xffff,
                     ext);
        } else if (bestaka->point) {
            snprintf(p, remaining, "/%04x%04x.%s0",
                     ((bestaka->net) - (addr->net)) & 0xffff,
                     ((bestaka->node) - (addr->node) - (bestaka->point)) & 0xffff,
                     ext);
        } else {
            snprintf(p, remaining, "/%04x%04x.%s0",
                     ((bestaka->net) - (addr->net)) & 0xffff,
                     ((bestaka->node) - (addr->node)) & 0xffff, ext);
        }
    }

    if (bestaka != NULL)
        tidy_faddr(bestaka);
    return buf;
}
