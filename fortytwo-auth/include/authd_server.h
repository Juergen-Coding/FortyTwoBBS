/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Unix-socket server loop for fortytwo-authd phase B2.
 */

#ifndef FORTYTWO_AUTHD_SERVER_H
#define FORTYTWO_AUTHD_SERVER_H

#include "authd_config.h"
#include "authd_database.h"

int authd_server_run(const authd_config_t *config,
                     authd_database_t *database);

#endif /* FORTYTWO_AUTHD_SERVER_H */
