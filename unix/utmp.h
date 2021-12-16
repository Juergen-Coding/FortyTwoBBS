/* $Id: utmp.h,v 1.4 2004/12/28 15:30:53 mbse Exp $ */

#ifndef	_UTMP_HH
#define	_UTMP_HH


void checkutmp(int);
void setutmp(const char *, const char *, const char *);

#endif
