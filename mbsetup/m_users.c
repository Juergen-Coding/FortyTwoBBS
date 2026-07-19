/*****************************************************************************
 *
 * $Id: m_users.c,v 1.34 2007/02/25 20:55:33 mbse Exp $
 * Purpose ...............: Edit Users
 *
 *****************************************************************************
 * Copyright (C) 1997-2007
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
 * MB BBS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with MB BBS; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *****************************************************************************/

#include "../lib/mbselib.h"
#include "../lib/users.h"
#include <limits.h>
#include "screen.h"
#include "mutil.h"
#include "ledit.h"
#include "m_lang.h"
#include "m_global.h"
#include "m_archive.h"
#include "m_protocol.h"
#include "m_users.h"



int	UsrUpdated = 0;


/*
 * Validate the users database header and calculate the exact record count.
 * Older, smaller records may be upgraded. Larger records are rejected so an
 * older mbsetup cannot silently discard fields from a newer database format.
 */
static int ValidateUsersDatabase(FILE *fil, const char *path, int *records)
{
    struct userhdr header;
    struct stat st;
    off_t payload;

    if (fstat(fileno(fil), &st) != 0) {
        WriteError("$Cannot stat %s", path);
        return -1;
    }

    if (st.st_size == 0) {
        WriteError("%s is empty", path);
        return -1;
    }

    if (fseeko(fil, 0, SEEK_SET) != 0 ||
        fread(&header, sizeof(header), 1, fil) != 1) {
        WriteError("$Cannot read users database header from %s", path);
        return -1;
    }

    if (header.hdrsize != (int)sizeof(header)) {
        WriteError("Unsupported users database header size %d in %s",
                   header.hdrsize, path);
        return -1;
    }

    if (header.recsize <= 0 || header.recsize > (int)sizeof(usrconfig)) {
        WriteError("Invalid users database record size %d in %s",
                   header.recsize, path);
        return -1;
    }

    if ((off_t)header.hdrsize > st.st_size) {
        WriteError("Users database header exceeds file size in %s", path);
        return -1;
    }

    payload = st.st_size - (off_t)header.hdrsize;
    if ((payload % header.recsize) != 0) {
        WriteError("Incomplete users database record in %s", path);
        return -1;
    }

    if ((payload / header.recsize) > INT_MAX) {
        WriteError("Too many users database records in %s", path);
        return -1;
    }

    if (fseeko(fil, header.hdrsize, SEEK_SET) != 0) {
        WriteError("$Cannot seek to users database records in %s", path);
        return -1;
    }

    usrconfighdr = header;
    *records = (int)(payload / header.recsize);
    return 0;
}



/*
 * Write a new users database header to an already opened empty file.
 */
static int InitializeUsersDatabase(FILE *fil, const char *path)
{
    memset(&usrconfighdr, 0, sizeof(usrconfighdr));
    usrconfighdr.hdrsize = sizeof(usrconfighdr);
    usrconfighdr.recsize = sizeof(usrconfig);

    if (fseeko(fil, 0, SEEK_SET) != 0 ||
        fwrite(&usrconfighdr, sizeof(usrconfighdr), 1, fil) != 1 ||
        fflush(fil) != 0 || fsync(fileno(fil)) != 0) {
        WriteError("$Cannot initialize %s", path);
        return -1;
    }

    return 0;
}



/*
 * Legacy user records store fixed-width character arrays. Always terminate
 * every string field after reading an untrusted record.
 */
static void TerminateUserRecordStrings(struct userrec *user)
{
    int i;

    user->sUserName[sizeof(user->sUserName) - 1] = '\0';
    user->Name[sizeof(user->Name) - 1] = '\0';
    user->sVoicePhone[sizeof(user->sVoicePhone) - 1] = '\0';
    user->sDataPhone[sizeof(user->sDataPhone) - 1] = '\0';
    user->sLocation[sizeof(user->sLocation) - 1] = '\0';
    for (i = 0; i < 3; i++)
        user->address[i][sizeof(user->address[i]) - 1] = '\0';
    user->sDateOfBirth[sizeof(user->sDateOfBirth) - 1] = '\0';
    user->sComment[sizeof(user->sComment) - 1] = '\0';
    user->sExpiryDate[sizeof(user->sExpiryDate) - 1] = '\0';
    user->sSex[sizeof(user->sSex) - 1] = '\0';
    user->Archiver[sizeof(user->Archiver) - 1] = '\0';
    user->sProtocol[sizeof(user->sProtocol) - 1] = '\0';
    user->sHandle[sizeof(user->sHandle) - 1] = '\0';
    user->Password[sizeof(user->Password) - 1] = '\0';
    user->OLRlast[sizeof(user->OLRlast) - 1] = '\0';
}



/* The editable snapshot is always written in the current native format. */
static int ValidateEditableUsersDatabase(FILE *fil, const char *path,
                                         int *records)
{
    if (ValidateUsersDatabase(fil, path, records) != 0)
        return -1;

    if (usrconfighdr.hdrsize != (int)sizeof(usrconfighdr) ||
        usrconfighdr.recsize != (int)sizeof(usrconfig)) {
        WriteError("Unexpected editable users database format in %s", path);
        return -1;
    }

    return 0;
}



static int ReadUserRecord(FILE *fil, const char *path, int record_index)
{
    off_t offset;

    if (record_index < 0) {
        WriteError("Invalid users database record index in %s", path);
        return -1;
    }

    offset = (off_t)usrconfighdr.hdrsize +
        ((off_t)record_index * (off_t)usrconfighdr.recsize);
    if (fseeko(fil, offset, SEEK_SET) != 0) {
        WriteError("$Cannot seek to users database record %d in %s",
                   record_index + 1, path);
        return -1;
    }

    memset(&usrconfig, 0, sizeof(usrconfig));
    if (fread(&usrconfig, (size_t)usrconfighdr.recsize, 1, fil) != 1) {
        WriteError("$Cannot read users database record %d from %s",
                   record_index + 1, path);
        return -1;
    }

    TerminateUserRecordStrings(&usrconfig);
    return 0;
}



static int WriteUserRecord(FILE *fil, const char *path, int record_index)
{
    off_t offset;

    if (record_index < 0 ||
        usrconfighdr.hdrsize != (int)sizeof(usrconfighdr) ||
        usrconfighdr.recsize != (int)sizeof(usrconfig)) {
        WriteError("Invalid editable users database state for %s", path);
        return -1;
    }

    offset = (off_t)usrconfighdr.hdrsize +
        ((off_t)record_index * (off_t)usrconfighdr.recsize);
    if (fseeko(fil, offset, SEEK_SET) != 0) {
        WriteError("$Cannot seek to users database record %d in %s",
                   record_index + 1, path);
        return -1;
    }

    TerminateUserRecordStrings(&usrconfig);
    if (fwrite(&usrconfig, sizeof(usrconfig), 1, fil) != 1 ||
        fflush(fil) != 0 || fsync(fileno(fil)) != 0) {
        WriteError("$Cannot write users database record %d to %s",
                   record_index + 1, path);
        return -1;
    }

    return 0;
}



/*
 * Count nr of usrconfig records in the database.
 * Creates the database if it doesn't exist and initializes an existing empty
 * file. Malformed non-empty databases are rejected without modification.
 */
int CountUsers(void)
{
    FILE    *fil;
    char    ffile[PATH_MAX];
    int     count = 0;
    int     fd = -1;
    int     flags = O_RDWR | O_CREAT | O_EXCL;
    int     created = FALSE;
    int     saved_errno;
    struct stat st;

#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    snprintf(ffile, PATH_MAX, "%s/etc/users.data", getenv("MBSE_ROOT"));
    fil = fopen(ffile, "r+b");
    if (fil == NULL) {
        if (errno != ENOENT)
            return -1;

        fd = open(ffile, flags, 0660);
        if (fd == -1)
            return -1;

        if (fchmod(fd, 0660) != 0 || (fil = fdopen(fd, "w+b")) == NULL) {
            saved_errno = errno;
            close(fd);
            unlink(ffile);
            errno = saved_errno;
            return -1;
        }
        fd = -1;
        created = TRUE;
    }

    if (fstat(fileno(fil), &st) != 0) {
        fclose(fil);
        if (created)
            unlink(ffile);
        return -1;
    }

    if (st.st_size == 0) {
        if (InitializeUsersDatabase(fil, ffile) != 0) {
            fclose(fil);
            if (created)
                unlink(ffile);
            return -1;
        }
        if (fclose(fil) != 0) {
            if (created)
                unlink(ffile);
            return -1;
        }
        Syslog('+', "%s %s", created ? "Created" : "Initialized", ffile);
        return 0;
    }

    if (ValidateUsersDatabase(fil, ffile, &count) != 0) {
        fclose(fil);
        return -1;
    }

    if (fclose(fil) != 0)
        return -1;

    return count;
}



/*
 * Open database for editing. The datafile is copied, if the format
 * is changed it will be converted on the fly. All editing must be
 * done on the copied file.
 */
int OpenUsers(void);
int OpenUsers(void)
{
    FILE    *fin = NULL, *fout = NULL;
    char    fnin[PATH_MAX], fnout[PATH_MAX];
    int     oldsize;
    int     records;
    int     i;
    int     fd = -1;
    int     flags = O_WRONLY | O_CREAT | O_EXCL;
    int     temp_created = FALSE;

#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    snprintf(fnin,  PATH_MAX, "%s/etc/users.data", getenv("MBSE_ROOT"));
    snprintf(fnout, PATH_MAX, "%s/etc/users.temp", getenv("MBSE_ROOT"));

    fin = fopen(fnin, "rb");
    if (fin == NULL) {
        WriteError("$Cannot open %s", fnin);
        return -1;
    }

    if (ValidateUsersDatabase(fin, fnin, &records) != 0)
        goto failure;

    oldsize = usrconfighdr.recsize;
    fd = open(fnout, flags, 0660);
    if (fd == -1) {
        WriteError("$Cannot create %s", fnout);
        goto failure;
    }
    temp_created = TRUE;

    if (fchmod(fd, 0660) != 0 || (fout = fdopen(fd, "wb")) == NULL) {
        WriteError("$Cannot secure %s", fnout);
        goto failure;
    }
    fd = -1;

    usrconfighdr.hdrsize = sizeof(usrconfighdr);
    usrconfighdr.recsize = sizeof(usrconfig);
    if (fwrite(&usrconfighdr, sizeof(usrconfighdr), 1, fout) != 1) {
        WriteError("$Cannot write users database header to %s", fnout);
        goto failure;
    }

    for (i = 0; i < records; i++) {
        memset(&usrconfig, 0, sizeof(usrconfig));
        if (fread(&usrconfig, oldsize, 1, fin) != 1) {
            WriteError("$Cannot read users database record %d from %s",
                       i + 1, fnin);
            goto failure;
        }
        TerminateUserRecordStrings(&usrconfig);
        if (fwrite(&usrconfig, sizeof(usrconfig), 1, fout) != 1) {
            WriteError("$Cannot write users database record %d to %s",
                       i + 1, fnout);
            goto failure;
        }
    }

    if (fflush(fout) != 0 || fsync(fileno(fout)) != 0) {
        WriteError("$Cannot flush %s", fnout);
        goto failure;
    }

    if (fclose(fout) != 0) {
        fout = NULL;
        WriteError("$Cannot close %s", fnout);
        goto failure;
    }
    fout = NULL;

    if (fclose(fin) != 0) {
        fin = NULL;
        WriteError("$Cannot close %s", fnin);
        goto failure;
    }
    fin = NULL;

    UsrUpdated = (oldsize != (int)sizeof(usrconfig));
    if (UsrUpdated)
        Syslog('+', "Upgraded %s, format changed", fnin);

    return 0;

failure:
    if (fout != NULL)
        fclose(fout);
    else if (fd != -1)
        close(fd);
    if (fin != NULL)
        fclose(fin);
    if (temp_created)
        unlink(fnout);
    return -1;
}



int CloseUsers(int);
int CloseUsers(int force)
{
    char    fin[PATH_MAX], fout[PATH_MAX];
    int     save_changes = FALSE;

    snprintf(fin,  PATH_MAX, "%s/etc/users.data", getenv("MBSE_ROOT"));
    snprintf(fout, PATH_MAX, "%s/etc/users.temp", getenv("MBSE_ROOT"));

    if (UsrUpdated == 1)
        save_changes = force ||
            (yes_no((char *)"Database is changed, save changes") == 1);

    if (save_changes) {
        working(1, 0, 0);
        if (rename(fout, fin) != 0) {
            WriteError("$Cannot replace %s with %s", fin, fout);
            working(2, 0, 0);
            return -1;
        }
        UsrUpdated = 0;
        Syslog('+', "Updated \"users.data\"");
        if (!force)
            working(6, 0, 0);
        return 0;
    }

    if (unlink(fout) != 0 && errno != ENOENT) {
        WriteError("$Cannot remove %s", fout);
        return -1;
    }
    if (chmod(fin, 0660) != 0) {
        WriteError("$Cannot set permissions on %s", fin);
        return -1;
    }

    UsrUpdated = 0;
    return 0;
}



void Screen1(void)
{
        clr_index();
        set_color(WHITE, BLACK);
        mbse_mvprintw( 4, 2, "15. EDIT USER");
        set_color(CYAN, BLACK);
        mbse_mvprintw( 6, 2, "1.  Full Name");
        mbse_mvprintw( 7, 2, "2.  Security");
        mbse_mvprintw( 8, 2, "3.  Expirydate");
        mbse_mvprintw( 9, 2, "4.  Expiry Sec");
        mbse_mvprintw(10, 2, "    Unix name");
	mbse_mvprintw(11, 2, "    1st login");
	mbse_mvprintw(12, 2, "    Last login");
	mbse_mvprintw(13, 2, "    Pwdchange");
        mbse_mvprintw(14, 2, "5.  Credit");
        mbse_mvprintw(15, 2, "6.  Hidden");
	mbse_mvprintw(16, 2, "7.  Deleted");
	mbse_mvprintw(17, 2, "8.  No Kill");
	mbse_mvprintw(18, 2, "9.  Comment");

        mbse_mvprintw( 6,54, "10. Locked");
        mbse_mvprintw( 7,54, "11. Guest");
        mbse_mvprintw( 8,54, "12. Ext Info");
        mbse_mvprintw( 9,54, "13. Email");
	mbse_mvprintw(10,54, "    Calls");
	mbse_mvprintw(11,54, "    Downlds");
	mbse_mvprintw(12,54, "    Down Kb");
	mbse_mvprintw(13,54, "    Uploads");
	mbse_mvprintw(14,54, "    Upload Kb");
	mbse_mvprintw(15,54, "    Posted");
	mbse_mvprintw(16,54, "14. Time left");
	mbse_mvprintw(17,54, "15. Screen 2");
}



void Fields1(void)
{
        char    Date[30];
        struct  tm *ld;
	time_t	now;

        set_color(WHITE, BLACK);
	show_str( 6,17,35, usrconfig.sUserName);
	show_int( 7,17,    usrconfig.Security.level);
	show_str( 8,17,10, usrconfig.sExpiryDate);
	show_int( 9,17,    usrconfig.ExpirySec.level);
	set_color(LIGHTGRAY, BLACK);
	show_str(10,17, 8, usrconfig.Name);

	now = usrconfig.tFirstLoginDate;
        ld = localtime(&now);
		strftime(Date, 30, "%d-%m-%Y %H:%M:%S", ld);
        show_str(11,17,19, Date);
	now = usrconfig.tLastLoginDate;
        ld = localtime(&now);
		strftime(Date, 30, "%d-%m-%Y %H:%M:%S", ld);
        show_str(12,17,19, Date);
	now = usrconfig.tLastPwdChange;
	ld = localtime(&now);
	strftime(Date, 30, "%d-%m-%Y %H:%M:%S", ld);
	show_str(13,17,19, Date);
	
	set_color(WHITE, BLACK);
        show_int( 14,17,    usrconfig.Credit);
        show_bool(15,17,    usrconfig.Hidden);
	show_bool(16,17,    usrconfig.Deleted);
	show_bool(17,17,    usrconfig.NeverDelete);
	show_str( 18,17,63, usrconfig.sComment);

        show_bool( 6,68, usrconfig.LockedOut);
        show_bool( 7,68, usrconfig.Guest);
        show_bool( 8,68, usrconfig.OL_ExtInfo);
        show_bool( 9,68, usrconfig.Email);
	set_color(LIGHTGRAY, BLACK);
	show_int( 10,68, usrconfig.iTotalCalls);
	show_int( 11,68, usrconfig.Downloads);
	show_int( 12,68, usrconfig.DownloadK);
	show_int( 13,68, usrconfig.Uploads);
	show_int( 14,68, usrconfig.UploadK);
	show_int( 15,68, usrconfig.iPosted);
	set_color(WHITE, BLACK);
	show_int( 16,68, usrconfig.iTimeLeft);
}



void Screen2(void)
{
	clr_index();
	set_color(WHITE, BLACK);
	mbse_mvprintw( 4, 2, "15. EDIT USER PRIVATE SETTINGS");
	set_color(CYAN, BLACK);
	mbse_mvprintw( 6, 2, "1.  Handle");
	mbse_mvprintw( 7, 2, "2.  Location");
	mbse_mvprintw( 8, 2, "3.  Address 1");
	mbse_mvprintw( 9, 2, "4.  Address 2");
	mbse_mvprintw(10, 2, "5.  Address 3");
	mbse_mvprintw(11, 2, "6.  Voicephone");
	mbse_mvprintw(12, 2, "7.  Dataphone");
	mbse_mvprintw(13, 2, "8.  Birthdate");
	mbse_mvprintw(14, 2, "9.  Password");
	mbse_mvprintw(15, 2, "10. Sex");
	mbse_mvprintw(16, 2, "11. Protocol");
	mbse_mvprintw(17, 2, "12. Archiver");
	mbse_mvprintw(18, 2, "13. Charset");

	mbse_mvprintw( 6,58, "14. Language");
	mbse_mvprintw( 7,58, "15. Hotkeys");
	mbse_mvprintw( 8,58, "16. Color");
	mbse_mvprintw( 9,58, "17. Silent");
	mbse_mvprintw(10,58, "18. CLS");
	mbse_mvprintw(11,58, "19. More");
	mbse_mvprintw(12,58, "20. Editor");
	mbse_mvprintw(13,58, "21. MailScan");
	mbse_mvprintw(14,58, "22. ShowNews");
	mbse_mvprintw(15,58, "23. NewFiles");
	mbse_mvprintw(16,58, "24. Emacs");
	mbse_mvprintw(17,58, "25. OLRext");
}



void Fields2(void)
{
	char	temp[4];

	set_color(WHITE, BLACK);
	show_str( 6,17,35, usrconfig.sHandle);
	show_str( 7,17,27, usrconfig.sLocation);
	show_str( 8,17,40, usrconfig.address[0]);
	show_str( 9,17,40, usrconfig.address[1]);
	show_str(10,17,40, usrconfig.address[2]);
	show_str(11,17,19, usrconfig.sVoicePhone);
	show_str(12,17,19, usrconfig.sDataPhone);
	show_str(13,17,10, usrconfig.sDateOfBirth);
	show_str(14,17,Max_passlen, (char *)"<disabled>");
	show_str( 15,17, 7,usrconfig.sSex);
	show_str( 16,17,12,usrconfig.sProtocol);
	show_str( 17,17, 5,usrconfig.Archiver);
	show_charset(18,17,usrconfig.Charset);

	snprintf(temp, 4, "%c",usrconfig.iLanguage);
	show_str(  6,71,1, temp);
	show_bool( 7,71,   usrconfig.HotKeys);
	show_bool( 8,71,   usrconfig.GraphMode);
	show_bool( 9,71,   usrconfig.DoNotDisturb);
	show_bool(10,71,   usrconfig.Cls);
	show_bool(11,71,   usrconfig.More);
	show_msgeditor(12,71, usrconfig.MsgEditor);
	show_bool(13,71,   usrconfig.MailScan);
	show_bool(14,71,   usrconfig.ieNEWS);
	show_bool(15,71,   usrconfig.ieFILE);
	show_bool(16,71,   usrconfig.FSemacs);
	show_int( 17,71,   usrconfig.OLRext);
}



int EditUsrRec2(void)
{
    int	    j = 0, ch;
    char    temp[PATH_MAX];

    Screen2();
    for (;;) {
        Fields2();
        j = select_menu(24);
        switch(j) {
            case 0: return 0;
            case 1: E_STR( 6,17,35,usrconfig.sHandle,  "The ^Handle^ of this user"); break;
            case 2: E_STR( 7,17,27,usrconfig.sLocation,"The users ^Location^"); break;
            case 3:
            case 4:
            case 5: E_STR(j+5,17,40,usrconfig.address[j-3],"^Address^"); break;
            case 6: E_STR(11,17,16, usrconfig.sVoicePhone, "The ^Voice Phone^ number of this user"); break;
            case 7: E_STR(12,17,16, usrconfig.sDataPhone,  "The ^Data Phone^ number of this user"); break;
            case 8: E_STR(13,17,10, usrconfig.sDateOfBirth,"The ^Date of Birth^ in DD-MM-YYYY format"); break;
            case 9:
		    errmsg((char *)"Password editing is disabled until centralized authentication is available");
		    break;
            case 10:showhelp((char *)"Toggle ^Sex^ with spacebar, press <Enter> when done.");
		    do {
			set_color(YELLOW, BLUE);
			show_str(15,17,7, usrconfig.sSex);
			ch = readkey(15, 17, YELLOW, BLUE);
			if (ch == ' ') {
			    if (strcmp(usrconfig.sSex, "Male") == 0)
				strcpy(usrconfig.sSex, "Female");
			    else {
				strcpy(usrconfig.sSex, "Male\0\0");
			    }
			}
		    } while (ch != KEY_ENTER && ch != '\012');
		    set_color(WHITE, BLACK);
		    show_str(15,17,7, usrconfig.sSex);
                    break;
            case 11:strcpy(temp, PickProtocol(15));
                    if (strlen(temp) != 0)
                        strcpy(usrconfig.sProtocol, temp);
                    clr_index();
                    Screen2();
                    break;
            case 12:strcpy(temp, PickArchive((char *)"15", TRUE));
                    if (strlen(temp) != 0)
                        strcpy(usrconfig.Archiver, temp);
                    clr_index();
                    Screen2();
                    break;
	    case 13:usrconfig.Charset = edit_charset(18,17, usrconfig.Charset); break;

	    case 14:usrconfig.iLanguage = PickLanguage((char *)"15.14");
		    clr_index();
		    Screen2();
		    break;
            case 15:E_BOOL( 7,71,usrconfig.HotKeys,      "Is user using ^HotKeys^ for menus"); break;
            case 16:E_BOOL( 8,71,usrconfig.GraphMode,    "Is user using ^ANSI^ color"); break;
            case 17:E_BOOL( 9,71,usrconfig.DoNotDisturb, "User will not be ^disturbed^"); break;
            case 18:E_BOOL(10,71,usrconfig.Cls,          "Send ^ClearScreen code^ to users terminal"); break;
            case 19:E_BOOL(11,71,usrconfig.More,         "User uses the ^More prompt^"); break;
            case 20:usrconfig.MsgEditor = edit_msgeditor(12,71,usrconfig.MsgEditor);
		    break;
            case 21:E_BOOL(13,71,usrconfig.MailScan,     "Don't check for ^new mail^"); break;
            case 22:E_BOOL(14,71,usrconfig.ieNEWS,       "Show ^News Bulletins^ when logging in"); break;
            case 23:E_BOOL(15,71,usrconfig.ieFILE,       "Show ^New Files^ when logging in"); break;
            case 24:E_BOOL(16,71,usrconfig.FSemacs,      "Use ^Emacs^ or Wordstar shorcut keys in FS editor"); break;
            case 25:E_INT( 17,71,usrconfig.OLRext,       "Next ^OLR^ packet extension"); break;
        }
    }
}


void Reset_Time(void);
void Reset_Time(void)
{
    char        *temp;
    FILE        *pLimits;
    struct stat st;
    off_t       payload;
    int         records;
    int         i;

    temp = calloc(PATH_MAX, sizeof(char));
    if (temp == NULL) {
        WriteError("Cannot allocate limits database path");
        return;
    }

    snprintf(temp, PATH_MAX, "%s/etc/limits.data", getenv("MBSE_ROOT"));
    if ((pLimits = fopen(temp, "rb")) == NULL) {
        WriteError("$Can't open %s", temp);
        free(temp);
        return;
    }

    if (fstat(fileno(pLimits), &st) != 0 ||
        fread(&LIMIThdr, sizeof(LIMIThdr), 1, pLimits) != 1 ||
        LIMIThdr.hdrsize < (int)sizeof(LIMIThdr) ||
        LIMIThdr.recsize <= 0 ||
        LIMIThdr.recsize > (int)sizeof(LIMIT) ||
        (off_t)LIMIThdr.hdrsize > st.st_size) {
        WriteError("Invalid limits database header in %s", temp);
        fclose(pLimits);
        free(temp);
        return;
    }

    payload = st.st_size - (off_t)LIMIThdr.hdrsize;
    if ((payload % LIMIThdr.recsize) != 0 ||
        (payload / LIMIThdr.recsize) > INT_MAX ||
        fseeko(pLimits, LIMIThdr.hdrsize, SEEK_SET) != 0) {
        WriteError("Invalid limits database records in %s", temp);
        fclose(pLimits);
        free(temp);
        return;
    }

    records = (int)(payload / LIMIThdr.recsize);
    for (i = 0; i < records; i++) {
        memset(&LIMIT, 0, sizeof(LIMIT));
        if (fread(&LIMIT, (size_t)LIMIThdr.recsize, 1, pLimits) != 1) {
            WriteError("$Cannot read limits database record %d from %s",
                       i + 1, temp);
            break;
        }
        if (LIMIT.Security == usrconfig.Security.level) {
            if (LIMIT.Time)
                usrconfig.iTimeLeft = LIMIT.Time;
            else
                usrconfig.iTimeLeft = 86400;
            usrconfig.iTimeUsed = 0;
            break;
        }
    }

    if (fclose(pLimits) != 0)
        WriteError("$Cannot close %s", temp);
    free(temp);
}


/*
 * Edit one record, return -1 if there are errors, 0 if ok.
 */
int EditUsrRec(int Area)
{
    FILE	    *fil;
    char	    mfile[PATH_MAX];
    int		    records;
    int		    j = 0;
    unsigned int    crc, crc1, level;

    clr_index();
    working(1, 0, 0);
    IsDoing("Edit Users");

    snprintf(mfile, PATH_MAX, "%s/etc/users.temp", getenv("MBSE_ROOT"));
    if ((fil = fopen(mfile, "rb")) == NULL) {
	working(2, 0, 0);
	return -1;
    }

    if (ValidateEditableUsersDatabase(fil, mfile, &records) != 0 ||
	Area < 1 || Area > records ||
	ReadUserRecord(fil, mfile, Area - 1) != 0) {
	fclose(fil);
	working(2, 0, 0);
	return -1;
    }

    if (fclose(fil) != 0) {
	WriteError("$Cannot close %s", mfile);
	working(2, 0, 0);
	return -1;
    }

    if (strlen(usrconfig.sUserName) == 0) {
	errmsg((char *)"You cannot edit an empty record");
	return -1;
    }

    crc = 0xffffffff;
    crc = upd_crc32((char *)&usrconfig, crc, sizeof(usrconfig));
    Screen1();

    for (;;) {
	Fields1();
	j = select_menu(15);
	switch(j) {
	case 0: crc1 = 0xffffffff;
		crc1 = upd_crc32((char *)&usrconfig, crc1, sizeof(usrconfig));
		if (crc != crc1) {
		    if (yes_no((char *)"Record is changed, save") == 1) {
			working(1, 0, 0);
			if ((fil = fopen(mfile, "r+b")) == NULL) {
			    working(2, 0, 0);
			    return -1;
			}
			if (ValidateEditableUsersDatabase(fil, mfile, &records) != 0 ||
			    Area < 1 || Area > records ||
			    WriteUserRecord(fil, mfile, Area - 1) != 0) {
			    fclose(fil);
			    working(2, 0, 0);
			    return -1;
			}
			if (fclose(fil) != 0) {
			    WriteError("$Cannot close %s", mfile);
			    working(2, 0, 0);
			    return -1;
			}
			UsrUpdated = 1;
			working(6, 0, 0);
		    }
		}
		IsDoing("Browsing Menu");
		return 0;
	case 1:	E_STR(  6,17,35,usrconfig.sUserName,      "The ^First and Last name^ of this user"); break;
	case 2:	level = usrconfig.Security.level;
		usrconfig.Security = edit_usec(7,17,usrconfig.Security, (char *)"15.2   EDIT USER SECURITY");
		Screen1();
		Fields1();
		if (level != usrconfig.Security.level) {
		    if (yes_no((char *)"Set time left for new level") == 1) {
			Reset_Time();
		    }
		}
		break;
	case 3 :E_STR(  8,17,10,usrconfig.sExpiryDate,    "The ^Expiry Date^ in DD-MM-YYYY format, 00-00-0000 is no expire"); break;
	case 4 :E_INT(  9,17,   usrconfig.ExpirySec.level,"The ^Expiry Level^ for this user"); break;
	case 5 :E_INT( 14,17,   usrconfig.Credit,         "Users ^Credit^"); break;
	case 6 :E_BOOL(15,17,   usrconfig.Hidden,         "Is user ^hidden^ on the BBS"); break;
	case 7 :E_BOOL(16,17,   usrconfig.Deleted,        "Is user marked for ^deletion^"); break;
	case 8 :E_BOOL(17,17,   usrconfig.NeverDelete,    "^Never delete^ this user"); break;
	case 9 :E_STR( 18,17,62,usrconfig.sComment,       "A ^Comment^ for this user"); break;

	case 10:E_BOOL( 6,68,   usrconfig.LockedOut,      "User is ^Locked Out^ of this BBS"); break;
	case 11:E_BOOL( 7,68,   usrconfig.Guest,          "This is a ^Guest^ account"); break;
	case 12:E_BOOL( 8,68,   usrconfig.OL_ExtInfo,     "Add ^Extended Message Info^ in OLR download"); break;
	case 13:E_BOOL( 9,68,   usrconfig.Email,          "User has a ^private email^ mailbox"); break;
	case 14:if (yes_no((char *)"Reset time left for today") == 1) {
		    Reset_Time();
		}
		break;
	case 15:EditUsrRec2();
		clr_index();
		Screen1();
		Fields1();
		break;
	}
    }
    return 0;
}



void EditUsers(void)
{
    int	    records, listed_records, i, o, x, y;
    int	    read_failed;
    char    pick[12];
    FILE    *fil;
    char    temp[PATH_MAX];
    char    line[81];

    clr_index();
    working(1, 0, 0);
    IsDoing("Browsing Menu");
    if (config_read() == -1) {
	working(2, 0, 0);
	return;
    }

    if (! check_free())
	return;

    records = CountUsers();
    if (records == -1) {
	working(2, 0, 0);
	open_bbs();
	return;
    }

    if (OpenUsers() == -1) {
	working(2, 0, 0);
	open_bbs();
	return;
    }
    o = 0;

    for (;;) {
	clr_index();
	set_color(WHITE, BLACK);
	mbse_mvprintw( 5, 3, "15.  USERS EDITOR");
	set_color(CYAN, BLACK);
	if (records != 0) {
	    snprintf(temp, PATH_MAX, "%s/etc/users.temp", getenv("MBSE_ROOT"));
	    working(1, 0, 0);
	    fil = fopen(temp, "rb");
	    if (fil == NULL ||
		ValidateEditableUsersDatabase(fil, temp, &listed_records) != 0 ||
		listed_records != records) {
		if (fil == NULL)
		    WriteError("$Cannot open %s", temp);
		else
		    fclose(fil);
		UsrUpdated = 0;
		CloseUsers(FALSE);
		working(2, 0, 0);
		open_bbs();
		return;
	    }

	    x = 2;
	    y = 7;
	    read_failed = FALSE;
	    set_color(CYAN, BLACK);
	    for (i = 1; i <= 20; i++) {
		if (i == 11) {
		    x = 42;
		    y = 7;
		}
		if ((o + i) <= records) {
		    if (ReadUserRecord(fil, temp, (o + i) - 1) != 0) {
			read_failed = TRUE;
			break;
		    }
		    if ((!usrconfig.Deleted) && strlen(usrconfig.sUserName))
			set_color(CYAN, BLACK);
		    else
			set_color(LIGHTBLUE, BLACK);
		    snprintf(line, sizeof(line), "%3d.  %-32s", o + i,
			     usrconfig.sUserName);
		    line[37] = 0;
		    mbse_mvprintw(y, x, line);
		    y++;
		}
	    }

	    if (fclose(fil) != 0) {
		WriteError("$Cannot close %s", temp);
		read_failed = TRUE;
	    }
	    if (read_failed) {
		UsrUpdated = 0;
		CloseUsers(FALSE);
		working(2, 0, 0);
		open_bbs();
		return;
	    }
	}
	strcpy(pick, select_pick(records, 20));
		
	if (strncmp(pick, "-", 1) == 0) {
	    if (CloseUsers(FALSE) != 0)
		working(2, 0, 0);
	    open_bbs();
	    return;
	}

	if (strncmp(pick, "N", 1) == 0) 
	    if ((o + 20) < records)
		o = o + 20;

	if (strncmp(pick, "P", 1) == 0)
	    if ((o - 20) >= 0)
		o = o - 20;

	if ((atoi(pick) >= 1) && (atoi(pick) <= records)) {
	    if (EditUsrRec(atoi(pick)) != 0) {
		UsrUpdated = 0;
		if (CloseUsers(FALSE) != 0)
		    working(2, 0, 0);
		open_bbs();
		return;
	    }
	    o = ((atoi(pick) - 1) / 20) * 20;
	}
    }
}



void InitUsers(void)
{
    if (CountUsers() == -1)
	return;
    if (OpenUsers() == -1)
	return;
    if (CloseUsers(TRUE) != 0)
	WriteError("Cannot initialize users database");
}



void users_doc(void)
{
    char    temp[PATH_MAX];
    char    datafile[PATH_MAX];
    FILE    *wp, *ip, *fp;
    int	    nr;
    int	    records;
    time_t  tt;

    snprintf(datafile, PATH_MAX, "%s/etc/users.data", getenv("MBSE_ROOT"));
    if ((fp = fopen(datafile, "rb")) == NULL)
	return;

    if (ValidateUsersDatabase(fp, datafile, &records) != 0) {
	fclose(fp);
	return;
    }

    ip = open_webdoc((char *)"users.html", (char *)"BBS Users", NULL);
    if (ip == NULL) {
	fclose(fp);
	return;
    }
    fprintf(ip, "<A HREF=\"index.html\">Main</A>\n");
    fprintf(ip, "<UL>\n");
		    
    for (nr = 0; nr < records; nr++) {
	if (ReadUserRecord(fp, datafile, nr) != 0)
	    break;
	snprintf(temp, 81, "user_%d.html", nr + 1);
	fprintf(ip, "<LI><A HREF=\"%s\">%s</A></LI>\n", temp, usrconfig.sUserName);
	if ((wp = open_webdoc(temp, (char *)"BBS User", usrconfig.sUserName))) {
	    fprintf(wp, "<A HREF=\"index.html\">Main</A>&nbsp;<A HREF=\"users.html\">Back</A>\n");
	    fprintf(wp, "<P>\n");
	    fprintf(wp, "<TABLE width='600' border='0' cellspacing='0' cellpadding='2'>\n");
	    fprintf(wp, "<COL width='30%%'><COL width='70%%'>\n");
	    fprintf(wp, "<TBODY>\n");
	    add_webtable(wp, (char *)"Fidonet Name", usrconfig.sUserName);
	    add_webtable(wp, (char *)"Unix Name", usrconfig.Name);
	    web_secflags(wp, (char *)"Security level", usrconfig.Security);
	    add_webtable(wp, (char *)"Expiry date", usrconfig.sExpiryDate);
	    web_secflags(wp, (char *)"Expiry security level", usrconfig.ExpirySec);
	    tt = (time_t)usrconfig.tFirstLoginDate;
	    add_webtable(wp, (char *)"First login date", ctime(&tt));
	    tt = (time_t)usrconfig.tLastLoginDate;
	    add_webtable(wp, (char *)"Last login date", ctime(&tt));
	    tt = (time_t)usrconfig.tLastPwdChange;
	    add_webtable(wp, (char *)"Last password change", ctime(&tt));
	    add_webdigit(wp, (char *)"Credit", usrconfig.Credit);
	    add_webtable(wp, (char *)"Hidden from lists", getboolean(usrconfig.Hidden));
	    add_webtable(wp, (char *)"Never delete", getboolean(usrconfig.NeverDelete));
	    add_webtable(wp, (char *)"Comment", usrconfig.sComment);
	    add_webtable(wp, (char *)"Locked out", getboolean(usrconfig.LockedOut));
	    add_webtable(wp, (char *)"Guest user", getboolean(usrconfig.Guest));
	    add_webtable(wp, (char *)"OLR Extended info", getboolean(usrconfig.OL_ExtInfo));
	    add_webtable(wp, (char *)"Has e-mail", getboolean(usrconfig.Email));
	    add_webdigit(wp, (char *)"Total calls", usrconfig.iTotalCalls);
	    add_webdigit(wp, (char *)"total downloads", usrconfig.Downloads);
	    add_webdigit(wp, (char *)"Downloaded KBytes", usrconfig.DownloadK);
	    add_webdigit(wp, (char *)"Total uploads", usrconfig.Uploads);
	    add_webdigit(wp, (char *)"Uploaded KBytes", usrconfig.UploadK);
	    add_webdigit(wp, (char *)"Posted messages", usrconfig.iPosted);
	    add_webdigit(wp, (char *)"Minutes left today", usrconfig.iTimeLeft);
	    fprintf(wp, "</TBODY>\n");
	    fprintf(wp, "</TABLE>\n");
	    fprintf(wp, "<H3>User personal settings</H3>\n");
	    fprintf(wp, "<TABLE width='600' border='0' cellspacing='0' cellpadding='2'>\n");
	    fprintf(wp, "<COL width='30%%'><COL width='70%%'>\n");
	    fprintf(wp, "<TBODY>\n");
	    add_webtable(wp, (char *)"Handle", usrconfig.sHandle);
	    add_webtable(wp, (char *)"Location", usrconfig.sLocation);
	    add_webtable(wp, (char *)"Address", usrconfig.address[0]);
	    add_webtable(wp, (char *)"Address", usrconfig.address[1]);
	    add_webtable(wp, (char *)"Address", usrconfig.address[2]);
	    add_webtable(wp, (char *)"Voice phone", usrconfig.sVoicePhone);
	    add_webtable(wp, (char *)"Data phone", usrconfig.sDataPhone);
	    add_webtable(wp, (char *)"Date of birth", usrconfig.sDateOfBirth);
	    add_webtable(wp, (char *)"Sex", usrconfig.sSex);
	    add_webtable(wp, (char *)"Protocol", usrconfig.sProtocol);
	    add_webtable(wp, (char *)"Archiver", usrconfig.Archiver);
	    add_webtable(wp, (char *)"Character set", getftnchrs(usrconfig.Charset));
	    snprintf(temp, 4, "%c", usrconfig.iLanguage);
	    add_webtable(wp, (char *)"Language", temp);
	    add_webtable(wp, (char *)"Use hotkeys", getboolean(usrconfig.HotKeys));
	    add_webtable(wp, (char *)"Use ANSI color", getboolean(usrconfig.GraphMode));
	    add_webtable(wp, (char *)"Do not disturb", getboolean(usrconfig.DoNotDisturb));
	    add_webtable(wp, (char *)"Clear Screen", getboolean(usrconfig.Cls));
	    add_webtable(wp, (char *)"More prompt", getboolean(usrconfig.More));
	    add_webtable(wp, (char *)"Message editor", getmsgeditor(usrconfig.MsgEditor));
	    add_webtable(wp, (char *)"Scan new mail", getboolean(usrconfig.MailScan));
	    add_webtable(wp, (char *)"Display news", getboolean(usrconfig.ieNEWS));
	    add_webtable(wp, (char *)"Display newfiles", getboolean(usrconfig.ieFILE));
	    add_webtable(wp, (char *)"Emacs editor keys", getboolean(usrconfig.FSemacs));
	    fprintf(wp, "</TBODY>\n");
	    fprintf(wp, "</TABLE>\n");
	    close_webdoc(wp);
	}
    }

    fprintf(ip, "</UL>\n");
    close_webdoc(ip);
	    
    if (fclose(fp) != 0)
	WriteError("$Cannot close %s", datafile);
}


