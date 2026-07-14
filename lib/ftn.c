/*****************************************************************************
 *
 * $Id: ftn.c,v 1.11 2005/10/11 20:49:42 mbse Exp $
 * Purpose ...............: Fidonet Technology Network functions
 * Remark ................: From ifmail with patches from P.Saratxaga
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
#include "users.h"
#include "mbsedb.h"


#ifndef MAXUSHORT
#define MAXUSHORT 65535
#endif
#ifndef BLANK_SUBS
#define BLANK_SUBS '.'
#endif


int	addrerror = 0;

void tidy_faddr(faddr *addr)
{
	if (addr == NULL) 
		return;
	if (addr->name) 
		free(addr->name);
	if (addr->domain) 
		free(addr->domain);
	free(addr);
}



faddr *parsefnode(char *s)
{
	faddr	addr, *tmp;
	char	*buf, *str, *p, *q, *n;
	int	good = 1;

	if (s == NULL) 
		return NULL;

	str = buf = xstrcpy(s);

	while (isspace(*str)) 
		str++;
	if (*(p=str+strlen(str)-1) == '\n') 
		*(p--) ='\0';
	while (isspace(*p)) 
		*(p--) = '\0';

	p=str + strlen(str) - 1;
	if (((*str == '(') && (*p == ')')) || ((*str == '\"') && (*p == '\"')) ||
	    ((*str == '\'') && (*p == '\'')) || ((*str == '<') && (*p == '>')) ||
	    ((*str == '[') && (*p == ']')) || ((*str == '{') && (*p == '}'))) {
		str++;
		*p = '\0';
	}

	memset(&addr, 0, sizeof(faddr));
	if ((p = strrchr(str,' '))) {
		n = str;
		str = p + 1;
		while (isspace(*p)) 
			*(p--) = '\0';
		if (!strcasecmp(p - 2," of")) 
			*(p-2) = '\0';
		else if (!strcasecmp(p - 1," @")) 
			*(p-1) = '\0';
		p -= 3;
		while (isspace(*p) || (*p == ',')) 
			*(p--) = '\0';
		if (strlen(n) > MAXNAME) 
			n[MAXNAME] = '\0';
		if (*n != '\0') 
			addr.name = xstrcpy(n);
	}

	if ((p = strrchr(str, '@'))) 
		*(p++) = '\0';
	else if ((p = strrchr(str,'%'))) 
		*(p++) = '\0';
	else if ((q = strrchr(str,'#'))) { 
		*(q++) = '\0'; 
		p = str; 
		str = q; 
	} else if (addr.name && (strrchr(addr.name,'@'))) {
		str = xstrcpy(addr.name);
		if ((p=strrchr(str,'@'))) 
			*(p++) = '\0';
		else if ((p=strrchr(str,'%'))) 
			*(p++) = '\0';
        } else 
		p = NULL;

	if (p && ((q = strchr(p,'.')))) 
		*q = '\0';

	addr.point = 0;
	addr.node = 0;
	addr.net = 0;
	addr.zone = 0;
	addr.domain = xstrcpy(p);

	if ((p = strchr(str, ':'))) {
		*(p++) = '\0';
		if (strspn(str, "0123456789") == strlen(str))
			addr.zone = atoi(str);
		else 
			if (strcmp(str,"*") == 0)
				addr.zone = -1;
			else 
				good = 0;
		str = p;
	}

	if ((p = strchr(str, '/'))) {
		*(p++) = '\0';
		if (strspn(str, "0123456789") == strlen(str))
			addr.net = atoi(str);
		else 
			if (strcmp(str, "*") == 0)
				addr.net = -1;
			else 
				good = 0;
		str = p;
	}

	if ((p=strchr(str, '.'))) {
		*(p++) = '\0';
		if (strspn(str, "0123456789") == strlen(str))
			addr.node = atoi(str);
		else 
			if (strcmp(str, "*") == 0)
				addr.node = -1;
			else 
				good = 0;
		str = p;
	} else {
		if (strspn(str, "0123456789") == strlen(str))
			addr.node = atoi(str);
		else 
			if (strcmp(str, "*") == 0)
				addr.node = -1;
			else 
				good = 0;
		str = NULL;
	}

	if (str) {
		if (strspn(str, "0123456789") == strlen(str))
			addr.point = atoi(str);
		else 
			if (strcmp(str, "*") == 0)
				addr.point = -1;
			else 
				good = 0;
	}

	if (buf) 
		free(buf);

	if (good) {
		tmp = (faddr *)malloc(sizeof(addr));
		tmp->name   = NULL;
		tmp->domain = addr.domain;
		tmp->point  = addr.point;
		tmp->node   = addr.node;
		tmp->net    = addr.net;
		tmp->zone   = addr.zone;
		return tmp;
	} else {
		if (addr.name) 
			free(addr.name);
		if (addr.domain) 
			free(addr.domain);
		return NULL;
	}
}



faddr *parsefaddr(char *s)
{
	faddr		*tmpaddr = NULL;
	parsedaddr	rfcaddr;
	int		gotzone = 0, gotnet = 0, gotnode = 0, gotpoint = 0;
	int		zone = 0, net = 0, noden = 0, point = 0;
	char		*domain = NULL, *freename = NULL;
	int		num;
	char		*p = NULL,*q = NULL,*t = NULL;
	int		l, quoted;
	FILE		*fp;

	rfcaddr.target    = NULL;
	rfcaddr.remainder = NULL;
	rfcaddr.comment   = NULL;

	if ((s == NULL) || (*s == '\0'))
		return NULL;
	t = xstrcpy(s);
	if (*(q=t+strlen(t)-1) == '\n')
		*q='\0';
	if (((*(p=t) == '(') && (*(q=p+strlen(p)-1) == ')')) || ((*p == '\"') && (*q == '\"'))) {
		p++;
		*q='\0';
	}

	if (strchr(s,'@') || strchr(s,'%') || strchr(s,'!'))
		rfcaddr = parserfcaddr(p);
	else {
		addrerror = 0;
		rfcaddr.target = xstrcpy(p);
	}
	free(t);
	if ((addrerror) || (rfcaddr.target == NULL))
		goto leave;

	if (getenv("MBSE_ROOT") == NULL) {
		WriteError("MBSE_ROOT is not set");
		goto leave;
	}
	p = xmalloc(PATH_MAX);
	if (snprintf(p, PATH_MAX, "%s/etc/domain.data", getenv("MBSE_ROOT")) >= PATH_MAX) {
		WriteError("Domain database path is too long");
		free(p);
		goto leave;
	}
	if ((fp = fopen(p, "r")) == NULL) {
		WriteError("$Can't open %s", p);
		free(p);
	} else {
		if (fread(&domainhdr, sizeof(domainhdr), 1, fp) != 1 ||
		    domainhdr.hdrsize < (int)sizeof(domainhdr) ||
		    domainhdr.recsize <= 0 ||
		    domainhdr.recsize > (int)sizeof(domtrans) ||
		    fseek(fp, domainhdr.hdrsize, SEEK_SET) != 0) {
			WriteError("$Invalid domain database header in %s", p);
			free(p);
		} else {
			free(p);
			p = rfcaddr.target;

			while (1) {
				size_t plen, ilen;

				memset(&domtrans, 0, sizeof(domtrans));
				if (fread(&domtrans, domainhdr.recsize, 1, fp) != 1)
					break;

				domtrans.ftndom[sizeof(domtrans.ftndom) - 1] = '\0';
				domtrans.intdom[sizeof(domtrans.intdom) - 1] = '\0';

				plen = strlen(p);
				ilen = strlen(domtrans.intdom);
				if ((ilen > 0) && (ilen <= plen) &&
				    (strcasecmp(domtrans.intdom,
						p + plen - ilen) == 0)) {
					p[plen - ilen] = '\0';
					q = xmalloc(strlen(p) +
						    strlen(domtrans.ftndom) + 1);
					strcpy(q, p);
					strcat(q, domtrans.ftndom);
					p = q;
					free(rfcaddr.target);
					rfcaddr.target = p;
					break;
				}
			}
		}
		fclose(fp);
	}

	if (((l = strlen(rfcaddr.target)) > 4) && (strcasecmp(rfcaddr.target + l - 4,".ftn") == 0)) {
		rfcaddr.target[l-4] = '\0';
	}

	for (p = strtok(rfcaddr.target, "."); p; p = strtok(NULL,".")) {
		if (((l = strlen(p + 1)) > 0) && (l <= 5) &&
		    (strspn(p + 1, "0123456789") == l)) {
			num = atol(p + 1);
			switch (*p) {
			case 'z':
			case 'Z':
				gotzone++;
				if (num > MAXUSHORT) 
					addrerror |= ADDR_BADTOKEN;
				zone = num;
				break;
			case 'n':
			case 'N':
				gotnet++;
				if (num > MAXUSHORT) 
					addrerror |= ADDR_BADTOKEN;
				net = num;
				break;
			case 'f':
			case 'F':
				gotnode++;
				if (num > MAXUSHORT) 
					addrerror |= ADDR_BADTOKEN;
				noden = num;
				break;
			case 'p':
			case 'P':
				gotpoint++;
				if (num > MAXUSHORT) 
					addrerror |= ADDR_BADTOKEN;
				point = num;
				break;
			default:
				if (gotnet && gotnode) {
					if (domain == NULL)
						domain = xstrcpy(p);
				} else 
					addrerror |= ADDR_BADTOKEN;
				break;
			}
		} else { /* not "cNNNN" token */
			if (gotnet && gotnode) {
				if (domain == NULL) 
					domain = xstrcpy(p);
			} else 
				addrerror |= ADDR_BADTOKEN;
		}
	}

	if ((gotzone > 1) || (gotnet != 1) || (gotnode != 1) || (gotpoint > 1)) {
		addrerror |= ADDR_BADSTRUCT;
	}

	if (addrerror) 
		goto leave;

	if (rfcaddr.remainder) {
		quoted = 0;
		if ((*(p = rfcaddr.remainder) == '\"') && (*(q = p + strlen(p) -1) == '\"')) {
			p++;
			*q='\0';
			quoted = 1;
		}
		if (strchr(p,'@') || strchr(p,'%') || strchr(p,'!')) {
			if (((q=strrchr(p,'%'))) && !strchr(p,'@'))
				*q = '@';
		} else if ((!quoted) && (!strchr(p, ' '))) {
			for (q = p; *q; q++) {
				if (*q == BLANK_SUBS)
					*q = ' ';
				else if (*q == '.') 
					*q = ' ';
				else if (*q == '_')
					*q = ' ';
			}
		}
		for (q = p; *q; q++) {
			if ((*q == '\\') && ((*(q+1) == '"') || ((*(q+1) == '\\') && (!quoted)))) {
				*q='\0';
				strcat(p, q+1);
			}
		}
		if (strspn(p," ") != strlen(p)) 
			freename = xstrcpy(p);
	}

	tmpaddr=(faddr*)malloc(sizeof(faddr));

	tmpaddr->zone=zone;
	tmpaddr->net=net;
	tmpaddr->node=noden;
	tmpaddr->point=point;
	tmpaddr->domain=domain;
	domain=NULL;
	tmpaddr->name=freename;
	freename=NULL;

leave:
	if (domain) 
		free(domain);
	if (freename) 
		free(freename);

	tidyrfcaddr(rfcaddr);
	return tmpaddr;
}



static int append_ftn_char(char *dst, size_t dst_size, size_t *used, char ch)
{
	if ((*used + 1) >= dst_size)
		return FALSE;

	dst[*used] = ch;
	(*used)++;
	dst[*used] = '\0';
	return TRUE;
}


static int encode_ftn_name(const char *name, char *dst, size_t dst_size)
{
	const unsigned char	*f;
	size_t			used = 0;
	int			quoted;

	dst[0] = '\0';
	quoted = ((!strchr(name, '@')) &&
		  (strchr(name, BLANK_SUBS) || strchr(name, '.') ||
		   strchr(name, '_')));

	if (quoted && !append_ftn_char(dst, dst_size, &used, '"'))
		return FALSE;

	for (f = (const unsigned char *)name; *f; f++) {
		switch (*f) {
		case '_':
		case '.':
			if (!append_ftn_char(dst, dst_size, &used, (char)*f))
				return FALSE;
			break;

		case ' ':
			if (!quoted) {
				if (!append_ftn_char(dst, dst_size, &used,
						     BLANK_SUBS))
					return FALSE;
			} else {
				if (!append_ftn_char(dst, dst_size, &used, '=') ||
				    !append_ftn_char(dst, dst_size, &used, '2') ||
				    !append_ftn_char(dst, dst_size, &used, '0'))
					return FALSE;
			}
			break;

		case ',':
			if (!quoted &&
			    !append_ftn_char(dst, dst_size, &used, '\\'))
				return FALSE;
			if (!append_ftn_char(dst, dst_size, &used, '=') ||
			    !append_ftn_char(dst, dst_size, &used, '2') ||
			    !append_ftn_char(dst, dst_size, &used, 'c'))
				return FALSE;
			break;

		case '@':
			if (quoted) {
				if (!append_ftn_char(dst, dst_size, &used, '"'))
					return FALSE;
				quoted = FALSE;
			}
			if (!append_ftn_char(dst, dst_size, &used, '%'))
				return FALSE;
			break;

		case '"':
			if (!append_ftn_char(dst, dst_size, &used, '\\') ||
			    !append_ftn_char(dst, dst_size, &used, (char)*f))
				return FALSE;
			break;

		case '>':
		case '<':
		case '\'':
			if (!quoted &&
			    !append_ftn_char(dst, dst_size, &used, '\\'))
				return FALSE;
			if (!append_ftn_char(dst, dst_size, &used, (char)*f))
				return FALSE;
			break;

		default:
			if (((*f > 0x29) && (*f < 0x3a)) ||
			    ((*f > 0x40) && (*f < 0x5b)) ||
			    ((*f > 0x60) && (*f < 0x7b))) {
				if (!append_ftn_char(dst, dst_size, &used,
						     (char)*f))
					return FALSE;
			} else {
				if (!quoted &&
				    !append_ftn_char(dst, dst_size, &used, '\\'))
					return FALSE;
				if (!append_ftn_char(dst, dst_size, &used,
						     (char)*f))
					return FALSE;
			}
			break;
		}
	}

	if (quoted && !append_ftn_char(dst, dst_size, &used, '"'))
		return FALSE;

	return append_ftn_char(dst, dst_size, &used, '@');
}


char *ascinode(faddr *a, int fl)
{
	static char	buf[128], *p;
	static char	*q;
	char		encoded_name[128];
	size_t		len;
	int		found = FALSE;
	FILE		*fp;

	if (a == NULL) {
		strcpy(buf,"<none>");
		return buf;
	}

	buf[0]='\0';
	if ((fl & 0x80) && (a->name)) {
		if ((strchr(a->name,'.')) || (strchr(a->name,'@')) ||
		    (strchr(a->name,'\'')) || (strchr(a->name,',')) ||
		    (strchr(a->name,'<')) || (strchr(a->name,'>')))
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "\"%s\" <", a->name);
		else
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s <", a->name);
	}

	if ((fl & 0x40) && (a->name)) {
		len = strlen(buf);
		if (!encode_ftn_name(a->name, encoded_name,
				     sizeof(encoded_name)) ||
		    (strlen(encoded_name) >= (sizeof(buf) - len))) {
			WriteError("FTN address name is too long");
		} else {
			memcpy(buf + len, encoded_name,
			       strlen(encoded_name) + 1);
		}
	}

	if ((fl & 0x01) && (a->point))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "p%u.", a->point);
	if (fl & 0x02)
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "f%u.", a->node);
	if (fl & 0x04)
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "n%u.", a->net);
	if ((fl & 0x08) && (a->zone))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "z%u.", a->zone);
	len = strlen(buf);
	if ((len > 0) && (buf[len - 1] == '.'))
		buf[len - 1] = '\0';

	if (fl & 0x10) {
		if (a->domain)
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%s", a->domain);
	}

	if (fl & 0x20) {
		if (a->domain) {
			if ((fl & 0x10) == 0)
				snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%s", a->domain);
		} else {
			if (SearchFidonet(a->zone))
				snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%s", fidonet.domain);
			else
				snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".fidonet");
		}

		p = calloc(128, sizeof(char));
		snprintf(p, 128, "%s/etc/domain.data", getenv("MBSE_ROOT"));
		if ((fp = fopen(p, "r")) == NULL) {
			WriteError("$Can't open %s", p);
		} else {
			if (fread(&domainhdr, sizeof(domainhdr), 1, fp) != 1 ||
			    domainhdr.recsize <= 0 ||
			    domainhdr.recsize > sizeof(domtrans)) {
				WriteError("$Invalid domain database header in %s", p);
			} else {
				while (1) {
					size_t buflen, ftndomlen;
					size_t prefixlen, intdomlen;

					memset(&domtrans, 0, sizeof(domtrans));
					if (fread(&domtrans, domainhdr.recsize,
						  1, fp) != 1)
						break;

					domtrans.ftndom[
					    sizeof(domtrans.ftndom) - 1] = '\0';
					domtrans.intdom[
					    sizeof(domtrans.intdom) - 1] = '\0';

					buflen = strlen(buf);
					ftndomlen = strlen(domtrans.ftndom);
					if ((ftndomlen > 0) &&
					    (ftndomlen <= buflen) &&
					    (strcasecmp(domtrans.ftndom,
						buf + buflen - ftndomlen) == 0)) {
						q = buf + buflen - ftndomlen;
						prefixlen = (size_t)(q - buf);
						intdomlen = strlen(domtrans.intdom);

						if (prefixlen + intdomlen <
						    sizeof(buf)) {
							memcpy(q, domtrans.intdom,
							       intdomlen + 1);
							found = TRUE;
						} else {
							WriteError(
							    "Domain translation result too long");
						}
						break;
					}
				}
			}
			fclose(fp);
		}
		free(p);
		if (!found) 
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".ftn");
	}

	if ((fl & 0x80) && (a->name))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ">");

	return buf;
}



/*
 * Return ASCII string for node, the bits in 'fl' set the
 * output format.
 */
char *ascfnode(faddr *a, int fl)
{
	static char buf[128];

	if (a == NULL) {
		strcpy(buf, "<none>");
		return buf;
	}

	buf[0] = '\0';
	if ((fl & 0x40) && (a->name))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),"%s of ",a->name);
	if ((fl & 0x08) && (a->zone))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),"%u:",a->zone);
	if (fl & 0x04)
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),"%u/",a->net);
	if (fl & 0x02)
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),"%u",a->node);
	if ((fl & 0x01) && (a->point))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),".%u",a->point);
	if ((fl & 0x10) && (a->domain))
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),"@%s",a->domain);
	return buf;
}



int metric(faddr *a1, faddr *a2)
{
	if ((a1 == NULL) || (a2 == NULL))
		return METRIC_MAX;
	if ((a1->domain != NULL) && (a2->domain != NULL) &&
	    (strcasecmp(a1->domain,a2->domain) != 0))
		return METRIC_DOMAIN;
	if ((a1->zone != 0) && (a2->zone != 0) &&
	    (a1->zone != a2->zone)) return METRIC_ZONE;
	if (a1->net   != a2->net)   return METRIC_NET;
	if (a1->node  != a2->node)  return METRIC_NODE;
	if (a1->point != a2->point) return METRIC_POINT;
	return METRIC_EQUAL;
}



/*
 * Convert mbse style to ifcico style.
 */
faddr *fido2faddr(fidoaddr aka)
{
	faddr	*fa;

	fa = (faddr *)xmalloc(sizeof(faddr));
	fa->name   = NULL;
	fa->domain = xstrcpy(aka.domain);;
	fa->zone   = aka.zone;
	fa->net    = aka.net;
	fa->node   = aka.node;
	fa->point  = aka.point;

	return fa;
}



/*
 * Convert ifcico style to mbse style
 */
fidoaddr *faddr2fido(faddr *aka)
{
	fidoaddr *Sys;

	if (aka == NULL)
		return NULL;
	Sys = (fidoaddr *)xmalloc(sizeof(fidoaddr));
	memset(Sys, 0, sizeof(*Sys));
	Sys->zone  = aka->zone;
	Sys->net   = aka->net;
	Sys->node  = aka->node;
	Sys->point = aka->point;
	if (aka->domain != NULL)
		snprintf(Sys->domain, 13, "%s", aka->domain);

	return Sys;
}



faddr *bestaka_s(faddr *addr)
{
	faddr	*best = NULL, *tmp;
	int	i, minmetric, wt;

	for (i = 0; i < 40; i++) {
		if (CFG.akavalid[i]) {
			best = fido2faddr(CFG.aka[i]);
			break;
		}
	}
	if ((addr == NULL) || (best == NULL))
		return best;
	minmetric = metric(addr, best);

	for (i = 0; i < 40; i++) {
		if (CFG.akavalid[i]) {
			tmp = fido2faddr(CFG.aka[i]);
			wt = metric(addr, tmp);
			tidy_faddr(tmp);

			if ((wt < minmetric) && ((best->point != 0) || (minmetric > METRIC_NODE))) {
				/*
				 * In the same network, use node address even when 
				 * routing to the node where we have a point address
				 */
				minmetric = wt;
				tidy_faddr(best);
				best = fido2faddr(CFG.aka[i]);
			}
		}
	}
	return best;
}



int is_local(faddr *addr)
{
    int	    i;
    faddr   *tmp;

    if (addr == NULL)
	return FALSE;

    for (i = 0; i < 40; i++) {
	if (!CFG.akavalid[i])
	    continue;
	tmp = fido2faddr(CFG.aka[i]);
	if (metric(tmp, addr) == METRIC_EQUAL) {
	    tidy_faddr(tmp);
	    return TRUE;
	}
	tidy_faddr(tmp);
    }
    return FALSE;
}



int chkftnmsgid(char *msgid)
{
	faddr *p;

	if (msgid == NULL)
		return 0;

	while (isspace(*msgid)) 
		msgid++;
	if ((p=parsefaddr(msgid))) {
		if (p->name && (strspn(p->name,"0123456789") == strlen(p->name)))
			return 1;
	} else if ((!strncmp(msgid,"<MSGID_",7)) || (!strncmp(msgid,"<NOMSGID_",9)) || (!strncmp(msgid,"<ftn_",5))) {
		return 1;
	}
	return 0;
}



