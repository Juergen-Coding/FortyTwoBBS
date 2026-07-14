/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_config.h"

#include "ftap_protocol.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
static void
set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }

    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static bool
parse_uintmax_value(const char *text, int base, uintmax_t *value)
{
    char *end = NULL;
    uintmax_t parsed;

    if (text == NULL || text[0] == '\0' || value == NULL || text[0] == '-') {
        return false;
    }

    errno = 0;
    parsed = strtoumax(text, &end, base);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }

    *value = parsed;
    return true;
}

static bool
parse_uid_value(const char *text, uid_t *uid)
{
    uintmax_t parsed;
    uid_t converted;

    if (!parse_uintmax_value(text, 10, &parsed)) {
        return false;
    }

    converted = (uid_t)parsed;
    if ((uintmax_t)converted != parsed || converted == (uid_t)-1) {
        return false;
    }

    *uid = converted;
    return true;
}

static bool
parse_gid_value(const char *text, gid_t *gid)
{
    uintmax_t parsed;
    gid_t converted;

    if (!parse_uintmax_value(text, 10, &parsed)) {
        return false;
    }

    converted = (gid_t)parsed;
    if ((uintmax_t)converted != parsed || converted == (gid_t)-1) {
        return false;
    }

    *gid = converted;
    return true;
}

static bool
parse_size_value(const char *text, size_t minimum, size_t maximum,
                 size_t *value)
{
    uintmax_t parsed;

    if (!parse_uintmax_value(text, 10, &parsed) ||
        parsed < minimum || parsed > maximum || parsed > SIZE_MAX) {
        return false;
    }

    *value = (size_t)parsed;
    return true;
}

static bool
parse_int_value(const char *text, int minimum, int maximum, int *value)
{
    uintmax_t parsed;

    if (!parse_uintmax_value(text, 10, &parsed) ||
        parsed < (uintmax_t)minimum || parsed > (uintmax_t)maximum ||
        parsed > (uintmax_t)INT_MAX) {
        return false;
    }

    *value = (int)parsed;
    return true;
}

static bool
parse_u32_value(const char *text, uint32_t minimum, uint32_t maximum,
                uint32_t *value)
{
    uintmax_t parsed;

    if (!parse_uintmax_value(text, 10, &parsed) ||
        parsed < minimum || parsed > maximum || parsed > UINT32_MAX) {
        return false;
    }

    *value = (uint32_t)parsed;
    return true;
}

static bool
parse_mode_value(const char *text, mode_t *mode)
{
    uintmax_t parsed;

    if (!parse_uintmax_value(text, 8, &parsed) || parsed > UINTMAX_C(0777)) {
        return false;
    }

    *mode = (mode_t)parsed;
    return true;
}

void
authd_config_defaults(authd_config_t *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(*config));
    (void)snprintf(config->socket_path, sizeof(config->socket_path), "%s",
                   FTAP_DEFAULT_SOCKET_PATH);
    config->socket_mode = (mode_t)0660;
    config->allowed_uids[0] = geteuid();
    config->allowed_uid_count = 1U;
    config->max_clients = 64U;
    config->backlog = 64;
    config->hello_timeout_ms = UINT32_C(5000);
}

bool
authd_config_uid_is_allowed(const authd_config_t *config, uid_t uid)
{
    size_t index;

    if (config == NULL) {
        return false;
    }

    for (index = 0U; index < config->allowed_uid_count; ++index) {
        if (config->allowed_uids[index] == uid) {
            return true;
        }
    }

    return false;
}

authd_config_result_t
authd_config_parse(authd_config_t *config,
                   int argc,
                   char *const argv[],
                   char *error,
                   size_t error_size)
{
    enum {
        OPTION_SOCKET_MODE = 1000,
        OPTION_SOCKET_GID,
        OPTION_ALLOW_UID,
        OPTION_MAX_CLIENTS,
        OPTION_BACKLOG,
        OPTION_HELLO_TIMEOUT,
        OPTION_CHECK_CONFIG,
        OPTION_VERBOSE,
        OPTION_VERSION
    };
    static const struct option options[] = {
        {"socket", required_argument, NULL, 's'},
        {"socket-mode", required_argument, NULL, OPTION_SOCKET_MODE},
        {"socket-gid", required_argument, NULL, OPTION_SOCKET_GID},
        {"allow-uid", required_argument, NULL, OPTION_ALLOW_UID},
        {"max-clients", required_argument, NULL, OPTION_MAX_CLIENTS},
        {"backlog", required_argument, NULL, OPTION_BACKLOG},
        {"hello-timeout-ms", required_argument, NULL, OPTION_HELLO_TIMEOUT},
        {"check-config", no_argument, NULL, OPTION_CHECK_CONFIG},
        {"verbose", no_argument, NULL, OPTION_VERBOSE},
        {"version", no_argument, NULL, OPTION_VERSION},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    bool explicit_uids = false;
    int option;

    if (config == NULL || argc < 1 || argv == NULL) {
        set_error(error, error_size, "invalid configuration arguments");
        return AUTHD_CONFIG_ERROR;
    }

    authd_config_defaults(config);
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }

    /* GNU getopt uses optind == 0 for a complete parser reset. */
    optind = 0;
    opterr = 0;

    while ((option = getopt_long(argc, argv, "hs:", options, NULL)) != -1) {
        switch (option) {
        case 'h':
            return AUTHD_CONFIG_HELP;
        case 's': {
            size_t length = strlen(optarg);
            if (length == 0U || length >= sizeof(config->socket_path)) {
                set_error(error, error_size,
                          "--socket path must contain 1..%zu bytes",
                          sizeof(config->socket_path) - 1U);
                return AUTHD_CONFIG_ERROR;
            }
            if (optarg[0] != '/') {
                set_error(error, error_size,
                          "--socket path must be absolute");
                return AUTHD_CONFIG_ERROR;
            }
            memcpy(config->socket_path, optarg, length + 1U);
            break;
        }
        case OPTION_SOCKET_MODE:
            if (!parse_mode_value(optarg, &config->socket_mode)) {
                set_error(error, error_size,
                          "--socket-mode must be octal between 0000 and 0777");
                return AUTHD_CONFIG_ERROR;
            }
            break;
        case OPTION_SOCKET_GID:
            if (!parse_gid_value(optarg, &config->socket_gid)) {
                set_error(error, error_size,
                          "--socket-gid must be a valid numeric GID");
                return AUTHD_CONFIG_ERROR;
            }
            config->socket_gid_set = true;
            break;
        case OPTION_ALLOW_UID: {
            uid_t uid;
            if (!parse_uid_value(optarg, &uid)) {
                set_error(error, error_size,
                          "--allow-uid must be a valid numeric UID");
                return AUTHD_CONFIG_ERROR;
            }
            if (!explicit_uids) {
                config->allowed_uid_count = 0U;
                explicit_uids = true;
            }
            if (config->allowed_uid_count >= AUTHD_MAX_ALLOWED_UIDS) {
                set_error(error, error_size,
                          "at most %u --allow-uid options are supported",
                          AUTHD_MAX_ALLOWED_UIDS);
                return AUTHD_CONFIG_ERROR;
            }
            if (!authd_config_uid_is_allowed(config, uid)) {
                config->allowed_uids[config->allowed_uid_count++] = uid;
            }
            break;
        }
        case OPTION_MAX_CLIENTS:
            if (!parse_size_value(optarg, AUTHD_MIN_CLIENTS,
                                  AUTHD_MAX_CLIENTS,
                                  &config->max_clients)) {
                set_error(error, error_size,
                          "--max-clients must be between %u and %u",
                          AUTHD_MIN_CLIENTS, AUTHD_MAX_CLIENTS);
                return AUTHD_CONFIG_ERROR;
            }
            break;
        case OPTION_BACKLOG:
            if (!parse_int_value(optarg, AUTHD_MIN_BACKLOG,
                                 AUTHD_MAX_BACKLOG, &config->backlog)) {
                set_error(error, error_size,
                          "--backlog must be between %u and %u",
                          AUTHD_MIN_BACKLOG, AUTHD_MAX_BACKLOG);
                return AUTHD_CONFIG_ERROR;
            }
            break;
        case OPTION_HELLO_TIMEOUT:
            if (!parse_u32_value(optarg, AUTHD_MIN_HELLO_TIMEOUT_MS,
                                 AUTHD_MAX_HELLO_TIMEOUT_MS,
                                 &config->hello_timeout_ms)) {
                set_error(error, error_size,
                          "--hello-timeout-ms must be between %" PRIu32
                          " and %" PRIu32,
                          AUTHD_MIN_HELLO_TIMEOUT_MS,
                          AUTHD_MAX_HELLO_TIMEOUT_MS);
                return AUTHD_CONFIG_ERROR;
            }
            break;
        case OPTION_CHECK_CONFIG:
            config->check_config = true;
            break;
        case OPTION_VERBOSE:
            config->verbose = true;
            break;
        case OPTION_VERSION:
            return AUTHD_CONFIG_VERSION;
        case '?':
        default:
            if (optopt != 0) {
                set_error(error, error_size, "unknown or incomplete option -%c",
                          optopt);
            } else {
                set_error(error, error_size, "unknown or incomplete option");
            }
            return AUTHD_CONFIG_ERROR;
        }
    }

    if (optind != argc) {
        set_error(error, error_size, "unexpected positional argument: %s",
                  argv[optind]);
        return AUTHD_CONFIG_ERROR;
    }

    if (config->allowed_uid_count == 0U) {
        set_error(error, error_size, "at least one allowed UID is required");
        return AUTHD_CONFIG_ERROR;
    }

    return AUTHD_CONFIG_OK;
}

void
authd_config_print_usage(FILE *stream, const char *program_name)
{
    const char *name = program_name != NULL ? program_name : "fortytwo-authd";

    if (stream == NULL) {
        return;
    }

    (void)fprintf(stream,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -s, --socket PATH          Unix socket path (default: %s)\n"
        "      --socket-mode OCTAL    Socket mode (default: 0660)\n"
        "      --socket-gid GID       Set socket group after bind\n"
        "      --allow-uid UID        Allow peer UID; repeatable\n"
        "      --max-clients N        Concurrent clients (1..256)\n"
        "      --backlog N            Listen backlog (1..4096)\n"
        "      --hello-timeout-ms N   HELLO deadline (100..300000)\n"
        "      --check-config         Validate and print configuration\n"
        "      --verbose              Log accepted/rejected peers\n"
        "      --version              Print version and exit\n"
        "  -h, --help                 Show this help\n",
        name, FTAP_DEFAULT_SOCKET_PATH);
}

void
authd_config_print_version(FILE *stream)
{
    if (stream != NULL) {
        (void)fprintf(stream, "fortytwo-authd %s (FTAP %u.%u)\n",
                      AUTHD_VERSION,
                      (unsigned int)FTAP_VERSION_MAJOR,
                      (unsigned int)FTAP_VERSION_MINOR);
    }
}

void
authd_config_print_effective(FILE *stream, const authd_config_t *config)
{
    size_t index;

    if (stream == NULL || config == NULL) {
        return;
    }

    (void)fprintf(stream, "socket=%s\n", config->socket_path);
    (void)fprintf(stream, "socket_mode=%04o\n",
                  (unsigned int)config->socket_mode);
    if (config->socket_gid_set) {
        (void)fprintf(stream, "socket_gid=%ju\n",
                      (uintmax_t)config->socket_gid);
    } else {
        (void)fprintf(stream, "socket_gid=unchanged\n");
    }
    (void)fprintf(stream, "max_clients=%zu\n", config->max_clients);
    (void)fprintf(stream, "backlog=%d\n", config->backlog);
    (void)fprintf(stream, "hello_timeout_ms=%" PRIu32 "\n",
                  config->hello_timeout_ms);
    (void)fprintf(stream, "verbose=%s\n", config->verbose ? "yes" : "no");
    for (index = 0U; index < config->allowed_uid_count; ++index) {
        (void)fprintf(stream, "allow_uid=%ju\n",
                      (uintmax_t)config->allowed_uids[index]);
    }
}
