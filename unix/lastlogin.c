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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sqlite3.h>
#include "lastlogin.h"


static const char database_name[] = "lastlogin.db";
static const size_t dbname_length = sizeof(database_name) / sizeof(char);
static const char create_table[] = "CREATE TABLE IF NOT EXISTS lastlogins (username TEXT UNIQUE PRIMARY KEY, terminal TEXT, hostname TEXT NULL, date TEXT);";
static const char query_table[] = "SELECT * FROM lastlogins WHERE username=?\0";
static const char insert_table[] = "INSERT INTO lastlogins (username, terminal, hostname, date) VALUES(?, ?, ?, datetime()) ON CONFLICT (username) DO UPDATE SET terminal=excluded.terminal, hostname=excluded.hostname, date=excluded.date\0";


static void lastlogin_free(struct lastlogin **);
static sqlite3 *open_lastlogin_db(void);

/* Initialize the database path name */
static char *get_lastlogin_dbname(int *error) {
    *error = 0;

    if (NULL == error) {
        return NULL;
    }

    char *mbse_root = getenv("MBSE_ROOT");
    if (NULL == mbse_root) {
        return NULL;
    }

    // Environment variables are null-terminated, so strlen is safe.
    size_t length = strlen(mbse_root) + 1;

    size_t total_length = length + 1 + dbname_length + 1;
    char *result = (char *)malloc(total_length);
    if (NULL == result) {
        *error = errno;
        return NULL;
    }

    // EXAMPLE of the below code:
    // mbse_root = /opt/mbse (9 characters/bytes)
    // database_name = lastlogin.db (11 characters/bytes)
    // length = 9
    // total_length = 22 (9 + 1 + 11 + 1)
    // result below becomes:
    // "/opt/mbse/lastlogin.db\0"

    strncpy(result, mbse_root, length);
    *(result + length - 1) = '/';
    strncpy(result + length, database_name, dbname_length);
    *(result + total_length - 1) = '\0';

    return result;
}

/* Create SQLite Database, precursor to processing the database */
static int create_lastlogin_db(sqlite3 *db) {
    char *errMsg;
    if (SQLITE_OK != sqlite3_exec(db, create_table, NULL, NULL, &errMsg)) {
        fprintf(stderr, "Error creating table in the database... %s\n", errMsg);
        sqlite3_free(errMsg);
        return -1;
    }

    return 0;
}

static sqlite3 *open_lastlogin_db(void) {
    int error;
    char *database_file = get_lastlogin_dbname(&error);
    if (NULL == database_file) {
        fprintf(stderr, "Error retrieving the database file name\n");
        return NULL;
    }

    sqlite3 *db;
    if (SQLITE_OK != sqlite3_open(database_file, &db)) {
        fprintf(stderr, "Error opening the database %s: %s\n", database_file, sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    free(database_file);

    if (0 != create_lastlogin_db(db)) {
        sqlite3_close(db);
        return NULL;
    }

    return db;
}

/* Retrieve Records for the user */
int get_lastlogin(const char *username, struct lastlogin **record) {
    if (NULL == record) {
        return EINVAL;
    }

    sqlite3 *db;

    if (NULL == (db = open_lastlogin_db())) {
        return -1;
    }

    sqlite3_stmt *statement;
    if (SQLITE_OK != sqlite3_prepare_v2(db, query_table, (sizeof(query_table) / sizeof(char)), &statement, NULL)) {
        fprintf(stderr, "Error creating database query statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    if (SQLITE_OK != sqlite3_bind_text(statement, 1, username, -1, SQLITE_STATIC)) {
        fprintf(stderr, "Unable to bind the username: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    int step_ret = sqlite3_step(statement);

    if (step_ret == SQLITE_ROW) {
        *record = (struct lastlogin *)calloc(1, sizeof(struct lastlogin));

        int username_len = sqlite3_column_bytes(statement, 0);
        int terminal_len = sqlite3_column_bytes(statement, 1);
        int hostname_len = sqlite3_column_bytes(statement, 2);
        int date_len = sqlite3_column_bytes(statement, 3);

        (*record)->username = strndup((char *)sqlite3_column_text(statement, 0), username_len + 1);
        (*record)->terminal = strndup((char *)sqlite3_column_text(statement, 1), terminal_len + 1);
        if (0 != hostname_len) {
            (*record)->hostname = strndup((char *)sqlite3_column_text(statement, 2), hostname_len + 1);
        }
        (*record)->date = strndup((char *)sqlite3_column_text(statement, 3), date_len + 1);
    } else if (step_ret != SQLITE_DONE) {
        // error
        fprintf(stderr, "Error when retrieving data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(statement);
        sqlite3_close(db);
        return -1;
    }

    if (SQLITE_OK != sqlite3_finalize(statement)) {
        fprintf(stderr, "Unable to delete the statement object: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    
    return 0;
}

int set_lastlogin(const char *username, const char *tty, const char *hostname) {
    struct lastlogin *record = (struct lastlogin *)calloc(1, sizeof(struct lastlogin));

    record->username = strdup(username);
    record->terminal = strdup(tty);
    if (hostname) { 
        record->hostname = strdup(hostname);
    }

    int ret = set_lastlogin_record(record);

    lastlogin_free(&record);

    return ret;
}

/* Create a record for the user, or update if needed */
int set_lastlogin_record(struct lastlogin *record) {
    if (NULL == record) {
        return EINVAL;
    }


    sqlite3 *db;

    if (NULL == (db = open_lastlogin_db())) {
        return -1;
    }

    sqlite3_stmt *statement;
    if (SQLITE_OK != sqlite3_prepare_v2(db, insert_table, (sizeof(insert_table) / sizeof(char)), &statement, NULL)) {
        fprintf(stderr, "Error creating database insert statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    if (SQLITE_OK != sqlite3_bind_text(statement, 1, record->username, -1, SQLITE_STATIC)) {
        fprintf(stderr, "Unable to bind the username: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    if (SQLITE_OK != sqlite3_bind_text(statement, 2, record->terminal, -1, SQLITE_STATIC)) {
        fprintf(stderr, "Unable to bind the terminal name: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    if (SQLITE_OK != sqlite3_bind_text(statement, 3, record->hostname, -1, SQLITE_STATIC)) {
        fprintf(stderr, "Unable to bind the hostname: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    int step_ret = sqlite3_step(statement);

    if (step_ret != SQLITE_DONE) {
        // error
        fprintf(stderr, "Error when retrieving data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(statement);
        sqlite3_close(db);
        return -1;
    }

    if (SQLITE_OK != sqlite3_finalize(statement)) {
        fprintf(stderr, "Unable to delete the statement object: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    
    return 0;
}


void lastlogin_free(struct lastlogin **record) {
    if (record && *record) {
        struct lastlogin *ll = *record;
        if (ll->username) free(ll->username);
        if (ll->terminal) free(ll->terminal);
        if (ll->hostname) free(ll->hostname);
        if (ll->date) free(ll->date);
        free(*record);
        *record = NULL;
    }
}
