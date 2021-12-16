/* SPDX-License-Identifier: GPL-2.0-only */

/*
    Copyright (C) 2021 MBSE Development Team

    This file is part of MBSE BBS.

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef __LASTLOGIN__H
#define __LASTLOGIN__H 1

struct lastlogin {
    char *username;       /* BBS (and system) user ID */
    char *terminal;       /* Terminal used */
    char *hostname;       /* Remote hostname, if any supplied (nullable) */
    char *date;           /* ISO8601 last date record (for readability) */
};

int get_lastlogin(const char *username, struct lastlogin **record);
int set_lastlogin_record(struct lastlogin *record);
int set_lastlogin(const char *username, const char *tty, const char *hostname);


#endif /* __LASTLOGIN__H */