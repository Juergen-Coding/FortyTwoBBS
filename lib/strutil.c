/*****************************************************************************
 *
 * $Id: strutil.c,v 1.16 2007/08/22 21:09:24 mbse Exp $
 * Purpose ...............: Common string functions
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
 * MB BBS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with MB BBS; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *****************************************************************************/

#include "mbselib.h"
#include <stdbool.h>



char *padleft(char *str, int size, char pad)
{
	static char stri[256];
	static char temp[256];

	strcpy(stri, str);
	memset(temp, pad, (size_t)size);
	temp[size] = '\0';
	if (strlen(stri) <= size)
		memmove(temp, stri, (size_t)strlen(stri));
	else
		memmove(temp, stri, (size_t)size);
	return temp;
}



/*
 * Small function to convert String to LowerCase
 */
char *tl(char *str)
{
	char	*p = str;

	while (*p != '\0') {
		*p = (char)tolower(*p);
		p++;
	}

	return str;
}




void Striplf(char *String)
{
	int i;

	for(i = 0; i < strlen(String); i++) {
		if(*(String + i) == '\0')
			break;
		if(*(String + i) == '\n')
			*(String + i) = '\0';
	}
}



void mbse_CleanSubject(char *String)
{
    int	    i, fixed = FALSE;

    i = strlen(String) -1;

    while ((isspace(String[i])) && i) {
	String[i] = '\0';
	i--;
	fixed = TRUE;
    }

    if ((strncasecmp(String, "Re: ", 4) == 0) && (strncmp(String, "Re: ", 4))) {
	/*
	 * Fix Re:
	 */
	String[0] = 'R';
	String[1] = 'e';
	String[2] = ':';
	String[3] = ' ';
	fixed = TRUE;
    }

    if (fixed)
	Syslog('m', "Fixed subj: \"%s\"", printable(String, 0));
}



/*
 * Converts first letter to UpperCase
 */
void tlf(char *str)
{
	*(str) = toupper(*(str));
}



/*
 * Small function to convert String to UpperCase
 */
char *tu(char *str)
{
	char	*p = str;

	while (*p != '\0') {
		*p = (char)toupper(*p);
		p++;
	}

	return str;
}



/*
 * Converts the first letter in every word in a string to uppercase,
 * all other character will be lowercase. Will handle the notation
 * Bob Ten.Dolle as well
 */
char *tlcap(char *String)
{
	static char	stri[256];
	int	Loop, Strlen;
	
	strcpy(stri, String);
	Strlen = strlen(stri);

	/*
	 * Automatic do the first character
	 */
	stri[0] = toupper(stri[0]);

	for(Loop = 1; Loop < Strlen; Loop++) {
		stri[Loop] = tolower(stri[Loop]);
		if (( stri[Loop] == ' ') || (stri[Loop] == '.')) {
			/* 
			 * This is a space charracter, increase the counter
			 * and convert the next character to uppercase.
			 */
			Loop++;
			stri[Loop] = toupper(stri[Loop]);
		}
	}
	return stri;
}



/*
 * Hilite "Word" in string, this is done by inserting ANSI
 * Hilite characters in the string.
 */
char *Hilite(char *str, char *Word)
{
	char *pos;
	char *new;
	char *old;
	int t;

	new = strdup(str);
	old = strdup(str);
	tl(new);

	if ((pos = strstr(new,Word)) == NULL)
		return(str);

	str = realloc(str,strlen(new)+200);
	strcpy(str,"\0");

	while (( pos = strstr(new,Word)) != NULL) {
		*pos = '\0';
		t = strlen(new);
		strncat(str,old,t);
		strcat(str,"[1;37m");
		old+=t;
		strncat(str,old,strlen(Word));
		strcat(str,"[0;37m");
		old+=strlen(Word);
		new = new+t+strlen(Word);
	}
	strcat(str,old);
	return(str);
}



/*
 * Replace spaces is a string with underscore characters.
 */
void Addunderscore(char *temp)
{
	int i;

	for(i = 0; i < strlen(temp); i++) {
		if (*(temp + i) == '\0')
			break;
		if (*(temp + i) == ' ')
			*(temp + i) = '_';
	}
}



/*
 * Find & Replace string in a string
 */
void strreplace(char *sStr, char *sFind, char *sReplace)
{
	char sNewstr[81]="";
	char *posStr, *posFind;
	int iPos, iLen, iCounter;

	posStr=sStr;
	if(( posFind = strstr(sStr, sFind)) != NULL) {
		iPos = (int)(posFind - posStr);
		strncpy(sNewstr, sStr, iPos);
		strcat(sNewstr, sReplace);
		iPos+= strlen(sFind);
		iLen = strlen(sNewstr);
		for (iCounter=0; iCounter < (strlen(sStr) - iPos); iCounter++)
			sNewstr[iCounter + iLen] = sStr[iCounter + iPos]; 
		sNewstr[iCounter+1+iLen] = '\0';
		strcpy(sStr, sNewstr);
	}
}



/*
 * Converts to HH:MM
 */
char *StrTimeHM(time_t date)
{
    static char	ttime[6];
    struct tm	*l_d;

    l_d = localtime(&date);
    snprintf(ttime, 6, "%02d:%02d", l_d->tm_hour, l_d->tm_min);
    return ttime;
}



/*
 * Returns HH:MM:SS
 */
char *StrTimeHMS(time_t date)
{
	static char	ttime[9];
	struct tm	*l_d;

	l_d = localtime(&date);
	snprintf(ttime, 9, "%02d:%02d:%02d", l_d->tm_hour, l_d->tm_min, l_d->tm_sec);
	return ttime;
}



/*
 * Get the current local time, returns HH:MM
 */
char *GetLocalHM() 
{
	static char	gettime[15];
	time_t		T_Now;

	T_Now = time(NULL);
	snprintf(gettime, 15, "%s", StrTimeHM(T_Now));
	return(gettime);
}




/*
 * Get the current local time, returns HH:MM:SS
 */
char *GetLocalHMS() 
{
	static char	gettime[15];
	time_t		T_Now;

	T_Now = time(NULL);
	snprintf(gettime, 15, "%s", StrTimeHMS(T_Now));
	return(gettime);
}



/* 
 * Returns date as MM-DD-YYYY
 */
char *StrDateMDY(time_t *Clock)
{
	struct tm *tm;
	static char cdate[15];
	
	tm = localtime(Clock);
	strftime(cdate, 15, "%m-%d-%Y", tm);
	return(cdate);
}



/*
 * Returns DD-MM-YYYY
 */
char *StrDateDMY(time_t date)
{
	static char	tdate[15];
	struct tm	*l_d;

	l_d = localtime(&date);
	strftime(tdate, 15, "%d-%m-%Y", l_d);
	return tdate;
}




/*
 * This function returns the date for today, to test against other functions
 *                 DD-MM-YYYY (DAY-MONTH-YEAR)
 */
char *GetDateDMY()
{
	return StrDateDMY(time(NULL));
}

#define sizeof_member(type, member) sizeof(((type *)0)->member)

/* On most POSIX-compliant environments this function will work; however,
 * on IBM i-Series and IBM AIX environments, it may return a CPU serial number
 * instead of an architecture name */
const struct utsname *get_sysinfo(void) {
  static struct utsname uts = { 0 };
  static bool isSet = false;
  if (false == isSet) {
    const size_t machine_size = sizeof_member(struct utsname, machine);
    const size_t sysname_size = sizeof_member(struct utsname, sysname);
    if (0 != uname(&uts)) {
      memccpy(uts.sysname, "Unknown", '\0', sysname_size);
      memccpy(uts.machine, "Unknown", '\0', machine_size);
    } else if (0 == strncmp(uts.sysname, "AIX", sysname_size)) {
      memccpy(uts.machine, "ppc", '\0', machine_size);
    } else if (0 == strncmp(uts.sysname, "OS400", sysname_size)) {
      memccpy(uts.machine, "Unknown", '\0', machine_size);
    }
    isSet = true;
  }

  return &uts;
}

const char *sys_name(void) {
  return (const char *)get_sysinfo()->sysname;
}

const char *cpu_arch(void) {
  return (const char *)get_sysinfo()->machine;
}

const char *versioned_sysinfo(void) {
	#define versioned_str_length (sizeof(VERSION) + sizeof_member(struct utsname, sysname) + sizeof_member(struct utsname, machine) + 8)
	static char versioned_str[versioned_str_length] = { 0 };
	static bool isSet = false;
	if (false == isSet) {
		snprintf(versioned_str, versioned_str_length, "%s (%s-%s)", VERSION, sys_name(), cpu_arch());
		isSet = true;
	}

	return (const char *)versioned_str;
	#undef versioned_str_length
}

/*
 * Return universal tearline, note if OS and CPU are
 * unknown, the tearline is already 39 characters.
 */
char *TearLine()
{
    static char	    tearline[45];

    snprintf(tearline, 45, "--- MBSE BBS v%.30s", versioned_sysinfo());
    return tearline;
}


