/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Local terminal login adapter for fortytwo-authd.
 */

#include "ftap_client.h"
#include "ftap_protocol.h"
#include "legacy_userdb.h"
#include "registration_coordinator.h"
#include "terminal_gate.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define FORTYTWO_LOGIN_VERSION "0.1.4"
#define LOGIN_LINE_BUFFER_SIZE (FTAP_LOGIN_NAME_MAX + 2U)
#define DISPLAY_LINE_BUFFER_SIZE (LEGACY_USERDB_DISPLAY_NAME_MAX + 2U)
#define PASSWORD_BUFFER_SIZE (FTAP_PASSWORD_MAX + 2U)
#define REGISTRATION_PASSWORD_MIN_BYTES 12U
#define TELNET_ISSUE_RELATIVE_PATH "etc/issue"
#define TELNET_ISSUE_MAX_BYTES (64U * 1024U)
#define DEFAULT_LEGACY_LANGUAGE 'D'
#define DEFAULT_LEGACY_CHARSET LEGACY_USERDB_CHARSET_CP437
#define DEFAULT_LEGACY_PROTOCOL "Zmodem"

typedef struct login_options {
    const char *socket_path;
    const char *protocol;
    const char *source_ip;
    const char *tty_device;
    const char *node_id;
    const char *mbse_root;
    const char *program;
    const char *bbs_users_directory;
    uint32_t timeout_ms;
    uint32_t legacy_security_level;
    bool registration_enabled;
    bool legacy_security_level_set;
} login_options_t;

typedef struct saved_environment {
    const char *name;
    char *value;
} saved_environment_t;

extern char **environ;

static volatile sig_atomic_t password_signal_number;

static void
password_signal_handler(int signal_number)
{
    password_signal_number = signal_number;
}

static void
secure_wipe(void *memory, size_t length)
{
    volatile unsigned char *bytes = memory;

    while (length > 0U) {
        *bytes++ = 0U;
        --length;
    }
}

static void
print_usage(FILE *stream, const char *program_name)
{
    (void)fprintf(
        stream,
        "Usage: %s --protocol telnet|ssh|local --mbse-root PATH [options]\n"
        "\n"
        "Options:\n"
        "  --socket PATH       fortytwo-authd socket (default: %s)\n"
        "  --source-ip IP      canonical IPv4 or IPv6 source address\n"
        "  --tty-device NAME   terminal device recorded for the session\n"
        "  --node-id NAME      optional terminal node identifier\n"
        "  --program PATH      program started after login\n"
        "  --enable-registration  enable NEW on Telnet (off by default)\n"
        "  --bbs-users-directory PATH  legacy user directory (required for NEW)\n"
        "  --legacy-security-level N  site new-user level (required for NEW)\n"
        "  --timeout-ms N      FTAP operation timeout (default: %u)\n"
        "  --version           print version\n"
        "  --help              print this help\n",
        program_name, FTAP_DEFAULT_SOCKET_PATH,
        FTAP_CLIENT_DEFAULT_TIMEOUT_MS);
}

static bool
parse_timeout(const char *text, uint32_t *timeout_ms)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed < 100UL || parsed > 300000UL) {
        return false;
    }
    *timeout_ms = (uint32_t)parsed;
    return true;
}

static bool
protocol_is_valid(const char *protocol)
{
    return protocol != NULL &&
           (strcmp(protocol, FTAP_PROTOCOL_TELNET) == 0 ||
            strcmp(protocol, FTAP_PROTOCOL_SSH) == 0 ||
            strcmp(protocol, FTAP_PROTOCOL_LOCAL) == 0);
}

static int
parse_options(int argc, char **argv, login_options_t *options)
{
    enum {
        OPTION_SOCKET = 1000,
        OPTION_PROTOCOL,
        OPTION_SOURCE_IP,
        OPTION_TTY_DEVICE,
        OPTION_NODE_ID,
        OPTION_MBSE_ROOT,
        OPTION_PROGRAM,
        OPTION_ENABLE_REGISTRATION,
        OPTION_BBS_USERS_DIRECTORY,
        OPTION_LEGACY_SECURITY_LEVEL,
        OPTION_TIMEOUT,
        OPTION_VERSION
    };
    static const struct option long_options[] = {
        {"socket", required_argument, NULL, OPTION_SOCKET},
        {"protocol", required_argument, NULL, OPTION_PROTOCOL},
        {"source-ip", required_argument, NULL, OPTION_SOURCE_IP},
        {"tty-device", required_argument, NULL, OPTION_TTY_DEVICE},
        {"node-id", required_argument, NULL, OPTION_NODE_ID},
        {"mbse-root", required_argument, NULL, OPTION_MBSE_ROOT},
        {"program", required_argument, NULL, OPTION_PROGRAM},
        {"enable-registration", no_argument, NULL, OPTION_ENABLE_REGISTRATION},
        {"bbs-users-directory", required_argument, NULL, OPTION_BBS_USERS_DIRECTORY},
        {"legacy-security-level", required_argument, NULL, OPTION_LEGACY_SECURITY_LEVEL},
        {"timeout-ms", required_argument, NULL, OPTION_TIMEOUT},
        {"version", no_argument, NULL, OPTION_VERSION},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int option;

    memset(options, 0, sizeof(*options));
    options->socket_path = FTAP_DEFAULT_SOCKET_PATH;
    options->timeout_ms = FTAP_CLIENT_DEFAULT_TIMEOUT_MS;

    while ((option = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (option) {
        case OPTION_SOCKET:
            options->socket_path = optarg;
            break;
        case OPTION_PROTOCOL:
            options->protocol = optarg;
            break;
        case OPTION_SOURCE_IP:
            options->source_ip = optarg;
            break;
        case OPTION_TTY_DEVICE:
            options->tty_device = optarg;
            break;
        case OPTION_NODE_ID:
            options->node_id = optarg;
            break;
        case OPTION_MBSE_ROOT:
            options->mbse_root = optarg;
            break;
        case OPTION_PROGRAM:
            options->program = optarg;
            break;
        case OPTION_ENABLE_REGISTRATION:
            options->registration_enabled = true;
            break;
        case OPTION_BBS_USERS_DIRECTORY:
            options->bbs_users_directory = optarg;
            break;
        case OPTION_LEGACY_SECURITY_LEVEL: {
            char *end = NULL;
            unsigned long parsed;

            errno = 0;
            parsed = strtoul(optarg, &end, 10);
            if (errno != 0 || end == optarg || *end != '\0' ||
                parsed == 0UL || parsed > UINT32_MAX) {
                (void)fprintf(stderr,
                              "fortytwo-login: invalid legacy security level\n");
                return -1;
            }
            options->legacy_security_level = (uint32_t)parsed;
            options->legacy_security_level_set = true;
            break;
        }
        case OPTION_TIMEOUT:
            if (!parse_timeout(optarg, &options->timeout_ms)) {
                (void)fprintf(stderr, "fortytwo-login: invalid timeout\n");
                return -1;
            }
            break;
        case OPTION_VERSION:
            (void)printf("fortytwo-login %s\n", FORTYTWO_LOGIN_VERSION);
            return 1;
        case 'h':
            print_usage(stdout, argv[0]);
            return 1;
        default:
            print_usage(stderr, argv[0]);
            return -1;
        }
    }

    if (optind != argc || !protocol_is_valid(options->protocol) ||
        options->mbse_root == NULL || options->mbse_root[0] != '/' ||
        options->socket_path == NULL || options->socket_path[0] != '/') {
        print_usage(stderr, argv[0]);
        return -1;
    }
    if (options->registration_enabled &&
        strcmp(options->protocol, FTAP_PROTOCOL_TELNET) != 0) {
        (void)fprintf(stderr,
                      "fortytwo-login: registration is Telnet-only\n");
        return -1;
    }
    if (options->registration_enabled &&
        (options->bbs_users_directory == NULL ||
         !options->legacy_security_level_set)) {
        (void)fprintf(stderr,
                      "fortytwo-login: registration requires users directory "
                      "and security level\n");
        return -1;
    }
    if (options->bbs_users_directory != NULL &&
        options->bbs_users_directory[0] != '/') {
        (void)fprintf(stderr,
                      "fortytwo-login: users directory must be absolute\n");
        return -1;
    }
    if (options->program != NULL && options->program[0] != '/') {
        (void)fprintf(stderr,
                      "fortytwo-login: program path must be absolute\n");
        return -1;
    }
    return 0;
}

/* Write raw banner bytes without passing ANSI sequences through stdio. */
static bool
write_all_bytes(int fd, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;
    size_t offset = 0U;

    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

/*
 * Display the trusted, optional Telnet issue file.  Symlinks, non-regular
 * files and banners larger than the fixed safety limit are ignored.
 */
static bool
display_telnet_issue(const char *mbse_root)
{
    unsigned char buffer[4096];
    struct stat status;
    char path[PATH_MAX];
    unsigned char last_byte = (unsigned char)'\n';
    size_t total = 0U;
    int length;
    int fd;

    length = snprintf(path, sizeof(path), "%s/%s", mbse_root,
                      TELNET_ISSUE_RELATIVE_PATH);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        return false;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return true;
    }

    if (fstat(fd, &status) != 0 ||
        !S_ISREG(status.st_mode) ||
        status.st_size < 0 ||
        (uintmax_t)status.st_size > (uintmax_t)TELNET_ISSUE_MAX_BYTES) {
        (void)close(fd);
        return true;
    }

    while (total < TELNET_ISSUE_MAX_BYTES) {
        size_t remaining = TELNET_ISSUE_MAX_BYTES - total;
        size_t requested = remaining < sizeof(buffer)
                               ? remaining
                               : sizeof(buffer);
        ssize_t received = read(fd, buffer, requested);

        if (received > 0) {
            if (!write_all_bytes(STDOUT_FILENO, buffer, (size_t)received)) {
                (void)close(fd);
                return false;
            }
            total += (size_t)received;
            last_byte = buffer[(size_t)received - 1U];
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    (void)close(fd);

    if (total > 0U && last_byte != (unsigned char)'\n' &&
        last_byte != (unsigned char)'\r') {
        return write_all_bytes(STDOUT_FILENO, "\r\n", 2U);
    }
    return true;
}

static bool
read_line(const char *prompt, char *buffer, size_t buffer_size)
{
    struct termios original;
    struct termios editing;
    size_t length = 0U;
    size_t overflow_length = 0U;
    bool echo_input;
    bool accepted = false;
    bool restored;

    if (prompt == NULL || buffer == NULL || buffer_size < 2U ||
        !isatty(STDIN_FILENO) ||
        tcgetattr(STDIN_FILENO, &original) != 0) {
        return false;
    }

    /*
     * Do not rely on the terminal's single VERASE setting. BBS clients may
     * send either Ctrl-H or DEL for Backspace, so editing is handled here.
     */
    editing = original;
    echo_input = (original.c_lflag & ECHO) != 0;
    editing.c_lflag &=
        (tcflag_t)~(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
    editing.c_cc[VMIN] = 1;
    editing.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &editing) != 0) {
        return false;
    }

    buffer[0] = '\0';
    (void)fputs(prompt, stdout);
    (void)fflush(stdout);

    for (;;) {
        unsigned char byte;
        ssize_t received = read(STDIN_FILENO, &byte, 1U);

        if (received < 0) {
            break;
        }
        if (received == 0) {
            break;
        }
        if (byte == '\r' || byte == '\n') {
            if (echo_input) {
                (void)fputs("\r\n", stdout);
                (void)fflush(stdout);
            }
            accepted = overflow_length == 0U && length > 0U;
            break;
        }
        if (byte == 0x08U || byte == 0x7fU) {
            if (overflow_length > 0U) {
                --overflow_length;
            } else if (length > 0U) {
                --length;
                buffer[length] = '\0';
                if (echo_input) {
                    (void)fputs("\b \b", stdout);
                    (void)fflush(stdout);
                }
            } else if (echo_input) {
                (void)fputc('\a', stdout);
                (void)fflush(stdout);
            }
            continue;
        }
        if (byte < 0x20U || byte == 0xffU) {
            continue;
        }
        if (length + 1U >= buffer_size) {
            if (overflow_length < SIZE_MAX) {
                ++overflow_length;
            }
            if (echo_input) {
                (void)fputc('\a', stdout);
                (void)fflush(stdout);
            }
            continue;
        }

        buffer[length++] = (char)byte;
        buffer[length] = '\0';
        if (echo_input) {
            (void)fputc((int)byte, stdout);
            (void)fflush(stdout);
        }
    }

    restored = tcsetattr(STDIN_FILENO, TCSANOW, &original) == 0;
    return accepted && restored;
}

/* Disable echo only while the password bytes are read from the terminal. */
static bool
read_password(const char *prompt, char *buffer, size_t buffer_size)
{
    static const int signals[] = {
        SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGTSTP
    };
    struct termios original;
    struct termios hidden;
    struct sigaction action;
    struct sigaction previous_actions[sizeof(signals) / sizeof(signals[0])];
    sigset_t blocked;
    sigset_t previous_mask;
    size_t installed = 0U;
    bool success = false;
    bool restored = false;
    int pending_signal;

    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original) != 0) {
        return false;
    }

    hidden = original;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    memset(&action, 0, sizeof(action));
    action.sa_handler = password_signal_handler;
    (void)sigemptyset(&action.sa_mask);
    (void)sigemptyset(&blocked);
    for (installed = 0U; installed < sizeof(signals) / sizeof(signals[0]);
         ++installed) {
        (void)sigaddset(&blocked, signals[installed]);
    }
    installed = 0U;

    /*
     * Install temporary handlers while the relevant signals are blocked. A
     * signal interrupts terminal input, after which echo is restored before
     * the original disposition receives the signal again.
     */
    if (sigprocmask(SIG_BLOCK, &blocked, &previous_mask) != 0) {
        return false;
    }
    while (installed < sizeof(signals) / sizeof(signals[0])) {
        if (sigaction(signals[installed], &action,
                      &previous_actions[installed]) != 0) {
            break;
        }
        ++installed;
    }
    if (installed != sizeof(signals) / sizeof(signals[0]) ||
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        while (installed > 0U) {
            --installed;
            (void)sigaction(signals[installed],
                            &previous_actions[installed], NULL);
        }
        (void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        return false;
    }

    password_signal_number = 0;
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) == 0) {
        if (password_signal_number == 0) {
            success = read_line(prompt, buffer, buffer_size);
        }
        if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) {
            success = false;
        }
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &original) == 0) {
        restored = true;
    }
    while (installed > 0U) {
        --installed;
        (void)sigaction(signals[installed],
                        &previous_actions[installed], NULL);
    }
    pending_signal = (int)password_signal_number;
    password_signal_number = 0;
    (void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    (void)fputs("\r\n", stdout);
    (void)fflush(stdout);

    if (pending_signal != 0) {
        (void)raise(pending_signal);
        return false;
    }
    return success && restored;
}

static bool
canonical_ip(const char *input, char output[INET6_ADDRSTRLEN])
{
    struct in_addr address4;
    struct in6_addr address6;

    if (input == NULL || input[0] == '\0') {
        return false;
    }
    if (inet_pton(AF_INET, input, &address4) == 1) {
        return inet_ntop(AF_INET, &address4, output, INET6_ADDRSTRLEN) != NULL;
    }
    if (inet_pton(AF_INET6, input, &address6) == 1) {
        return inet_ntop(AF_INET6, &address6, output, INET6_ADDRSTRLEN) != NULL;
    }
    return false;
}

static bool
first_word(const char *input, char *output, size_t output_size)
{
    size_t length;

    if (input == NULL) {
        return false;
    }
    length = strcspn(input, " \t");
    if (length == 0U || length >= output_size) {
        return false;
    }
    memcpy(output, input, length);
    output[length] = '\0';
    return true;
}

static const char *
derive_source_ip(const login_options_t *options,
                 char output[INET6_ADDRSTRLEN])
{
    char candidate[INET6_ADDRSTRLEN];
    const char *environment_value;

    if (options->source_ip != NULL) {
        return canonical_ip(options->source_ip, output) ? output : NULL;
    }
    if (strcmp(options->protocol, FTAP_PROTOCOL_SSH) == 0) {
        environment_value = getenv("SSH_CONNECTION");
        if (first_word(environment_value, candidate, sizeof(candidate)) &&
            canonical_ip(candidate, output)) {
            return output;
        }
        environment_value = getenv("SSH_CLIENT");
        if (first_word(environment_value, candidate, sizeof(candidate)) &&
            canonical_ip(candidate, output)) {
            return output;
        }
    }
    if (strcmp(options->protocol, FTAP_PROTOCOL_TELNET) == 0 &&
        canonical_ip(getenv("REMOTEHOST"), output)) {
        return output;
    }
    return NULL;
}

static const char *
derive_tty_device(const login_options_t *options,
                  char output[FTAP_TTY_DEVICE_MAX + 1U])
{
    if (options->tty_device != NULL) {
        return options->tty_device;
    }
    if (ttyname_r(STDIN_FILENO, output,
                  FTAP_TTY_DEVICE_MAX + 1U) == 0) {
        return output;
    }
    return NULL;
}

static void
print_client_error(const ftap_client_error_t *error, const char *protocol)
{
    if (error != NULL &&
        (error->protocol_error == FTAP_ERR_INVALID_CREDENTIALS ||
         error->protocol_error == FTAP_ERR_ACCOUNT_UNAVAILABLE)) {
        (void)fputs("Login failed.\r\n", stderr);
        return;
    }
    if (error != NULL && error->protocol_error == FTAP_ERR_ACCESS_DENIED) {
        if (protocol != NULL && strcmp(protocol, FTAP_PROTOCOL_SSH) == 0) {
            (void)fputs(
                "SSH access is not enabled for this account.\r\n",
                stderr);
        } else {
            (void)fputs("Access denied.\r\n", stderr);
        }
        return;
    }
    if (error != NULL && error->protocol_error == FTAP_ERR_RATE_LIMITED) {
        (void)fputs("Login temporarily unavailable.\r\n", stderr);
        return;
    }
    if (error != NULL && error->text[0] != '\0') {
        (void)fprintf(stderr, "fortytwo-login: %s\n", error->text);
    } else {
        (void)fputs("fortytwo-login: authentication service unavailable\n",
                    stderr);
    }
}

static void
free_saved_environment(saved_environment_t *saved, size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        free(saved[index].value);
        saved[index].value = NULL;
    }
}

/* Rebuild a small environment so identity and loader variables cannot leak in. */
static bool
sanitize_environment(const char *mbse_root)
{
    static const char *const preserved_names[] = {
        "TERM", "LANG", "LC_ALL", "LINES", "COLUMNS",
        "CONNECT", "CALLER_ID", "REMOTEHOST", "SSH_CLIENT",
        "SSH_CONNECTION"
    };
    saved_environment_t saved[sizeof(preserved_names) /
                              sizeof(preserved_names[0])];
    size_t index;
    bool success = true;

    memset(saved, 0, sizeof(saved));
    for (index = 0U; index < sizeof(preserved_names) /
                                sizeof(preserved_names[0]); ++index) {
        const char *value = getenv(preserved_names[index]);
        saved[index].name = preserved_names[index];
        if (value != NULL) {
            saved[index].value = strdup(value);
            if (saved[index].value == NULL) {
                success = false;
                break;
            }
        }
    }

    if (success && clearenv() != 0) {
        success = false;
    }
    if (success &&
        (setenv("MBSE_ROOT", mbse_root, 1) != 0 ||
         setenv("HOME", mbse_root, 1) != 0 ||
         setenv("PATH", "/usr/bin:/bin", 1) != 0 ||
         setenv("IFS", " \t\n", 1) != 0)) {
        success = false;
    }
    if (success) {
        for (index = 0U; index < sizeof(saved) / sizeof(saved[0]); ++index) {
            if (saved[index].value != NULL &&
                setenv(saved[index].name, saved[index].value, 1) != 0) {
                success = false;
                break;
            }
        }
    }

    free_saved_environment(saved, sizeof(saved) / sizeof(saved[0]));
    return success;
}

static void
close_unneeded_descriptors(void)
{
#if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range,
                (unsigned int)(FTAP_INHERITED_SESSION_FD + 1),
                ~0U, 0U) == 0) {
        return;
    }
#endif
    {
        struct rlimit limit;
        rlim_t maximum = 65536U;
        rlim_t descriptor;

        if (getrlimit(RLIMIT_NOFILE, &limit) == 0 &&
            limit.rlim_cur != RLIM_INFINITY) {
            maximum = limit.rlim_cur;
        }
        for (descriptor = (rlim_t)FTAP_INHERITED_SESSION_FD + 1U;
             descriptor < maximum; ++descriptor) {
            (void)close((int)descriptor);
        }
    }
}

static bool
ascii_word_is_new(const char *text)
{
    return text != NULL && text[0] != '\0' &&
           (text[0] == 'N' || text[0] == 'n') &&
           (text[1] == 'E' || text[1] == 'e') &&
           (text[2] == 'W' || text[2] == 'w') && text[3] == '\0';
}

static bool
registration_login_name_is_valid(const char *login_name)
{
    size_t length;
    size_t index;

    if (login_name == NULL) {
        return false;
    }
    length = strlen(login_name);
    if (length == 0U || length > FTAP_LOGIN_NAME_MAX ||
        !((login_name[0] >= 'a' && login_name[0] <= 'z') ||
          (login_name[0] >= '0' && login_name[0] <= '9'))) {
        return false;
    }
    for (index = 1U; index < length; ++index) {
        unsigned char value = (unsigned char)login_name[index];

        if (!((value >= (unsigned char)'a' &&
               value <= (unsigned char)'z') ||
              (value >= (unsigned char)'0' &&
               value <= (unsigned char)'9') ||
              value == (unsigned char)'.' ||
              value == (unsigned char)'_' ||
              value == (unsigned char)'-')) {
            return false;
        }
    }
    return true;
}

static void
initialize_legacy_defaults(legacy_userdb_record_defaults_t *defaults,
                           uint32_t security_level)
{
    memset(defaults, 0, sizeof(*defaults));
    defaults->security_level = security_level;
    defaults->language = DEFAULT_LEGACY_LANGUAGE;
    defaults->charset = DEFAULT_LEGACY_CHARSET;
    defaults->message_editor = LEGACY_USERDB_EDITOR_FULLSCREEN;
    defaults->protocol = DEFAULT_LEGACY_PROTOCOL;
    defaults->email = true;
    defaults->mail_scan = true;
    defaults->new_file_scan = true;
}

static void
print_registration_error(const fortytwo_registration_error_t *error)
{
    if (error != NULL && error->outcome_unknown) {
        (void)fputs(
            "Registration outcome is uncertain. Do not retry immediately; "
            "please contact the sysop.\r\n",
            stderr);
        return;
    }
    if (error != NULL && error->repair_required) {
        (void)fputs(
            "Registration needs sysop reconciliation. Please do not retry.\r\n",
            stderr);
        return;
    }
    if (error != NULL &&
        error->ftap.protocol_error == FTAP_ERR_RATE_LIMITED) {
        (void)fputs("Registration temporarily unavailable.\r\n", stderr);
        return;
    }
    (void)fputs("Registration could not be completed.\r\n", stderr);
}

static bool
collect_registration_input(char login_name[LOGIN_LINE_BUFFER_SIZE],
                           char display_name[DISPLAY_LINE_BUFFER_SIZE],
                           char password[PASSWORD_BUFFER_SIZE],
                           char password_repeat[PASSWORD_BUFFER_SIZE])
{
    terminal_gate_status_t challenge_status;

    challenge_status = registration_challenge_run(
        STDIN_FILENO, STDOUT_FILENO,
        REGISTRATION_CHALLENGE_DEFAULT_SECONDS,
        REGISTRATION_CHALLENGE_DEFAULT_ATTEMPTS);
    if (challenge_status != TERMINAL_GATE_OK) {
        return false;
    }

    if (!read_line("New login name: ", login_name,
                   LOGIN_LINE_BUFFER_SIZE)) {
        return false;
    }
    if (!registration_login_name_is_valid(login_name)) {
        (void)fputs(
            "Use 1-32 lowercase letters, digits, dot, underscore or hyphen.\r\n",
            stderr);
        return false;
    }
    if (!read_line("Display name: ", display_name,
                   DISPLAY_LINE_BUFFER_SIZE)) {
        return false;
    }
    if (!legacy_userdb_display_name_is_compatible(display_name)) {
        (void)fputs(
            "Display name must contain 1-35 UTF-8 bytes without control "
            "characters or outer spaces.\r\n",
            stderr);
        return false;
    }
    /*
     * Keep password corrections inside the registration dialog.  The
     * completed symbol challenge and the already entered names remain valid.
     */
    for (;;) {
        (void)fprintf(
            stdout,
            "Passwort: mind. %u Zeichen / "
            "Password: at least %u characters\r\n",
            REGISTRATION_PASSWORD_MIN_BYTES,
            REGISTRATION_PASSWORD_MIN_BYTES);

        if (!read_password("New password: ", password,
                           PASSWORD_BUFFER_SIZE)) {
            return false;
        }

        if (strlen(password) < REGISTRATION_PASSWORD_MIN_BYTES) {
            (void)fputs(
                "Passwort ist zu kurz / Password is too short. "
                "Please try again.\r\n",
                stderr);
            secure_wipe(password, PASSWORD_BUFFER_SIZE);
            secure_wipe(password_repeat, PASSWORD_BUFFER_SIZE);
            continue;
        }

        if (!read_password("Repeat password: ", password_repeat,
                           PASSWORD_BUFFER_SIZE)) {
            return false;
        }

        if (strcmp(password, password_repeat) != 0) {
            (void)fputs(
                "Passwoerter stimmen nicht ueberein / "
                "Passwords do not match. Please try again.\r\n",
                stderr);
            secure_wipe(password, PASSWORD_BUFFER_SIZE);
            secure_wipe(password_repeat, PASSWORD_BUFFER_SIZE);
            continue;
        }

        break;
    }

    return true;
}

/* Authenticate or register once, then replace the adapter preserving FD 3. */
static int
run_login(const login_options_t *options)
{
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_password_metadata_t metadata;
    ftap_registration_metadata_t registration_metadata;
    ftap_terminal_context_t result;
    fortytwo_registration_request_t registration_request;
    fortytwo_registration_result_t registration_result;
    fortytwo_registration_error_t registration_error;
    legacy_userdb_record_defaults_t legacy_defaults;
    legacy_userdb_provision_policy_t legacy_policy;
    char login_name[LOGIN_LINE_BUFFER_SIZE];
    char display_name[DISPLAY_LINE_BUFFER_SIZE];
    char password[PASSWORD_BUFFER_SIZE];
    char password_repeat[PASSWORD_BUFFER_SIZE];
    char source_ip[INET6_ADDRSTRLEN];
    char tty_device[FTAP_TTY_DEVICE_MAX + 1U];
    char default_program[PATH_MAX];
    const char *program = options->program;
    const char *bbs_users_directory = options->bbs_users_directory;
    char *child_argv[2];
    bool registration_requested = false;
    int64_t registration_time = 0;
    int exit_status = 1;

    memset(login_name, 0, sizeof(login_name));
    memset(display_name, 0, sizeof(display_name));
    memset(password, 0, sizeof(password));
    memset(password_repeat, 0, sizeof(password_repeat));
    memset(&metadata, 0, sizeof(metadata));
    memset(&registration_metadata, 0, sizeof(registration_metadata));
    memset(&result, 0, sizeof(result));
    memset(&registration_request, 0, sizeof(registration_request));
    fortytwo_registration_result_clear(&registration_result);
    fortytwo_registration_error_clear(&registration_error);
    initialize_legacy_defaults(&legacy_defaults,
                               options->legacy_security_level);
    legacy_userdb_provision_policy_defaults(&legacy_policy);
    ftap_client_init(&client, options->timeout_ms);
    ftap_client_error_clear(&error);

    if (program == NULL) {
        int length = snprintf(default_program, sizeof(default_program),
                              "%s/bin/mbsebbs", options->mbse_root);
        if (length < 0 || (size_t)length >= sizeof(default_program)) {
            (void)fputs("fortytwo-login: BBS path is too long\n", stderr);
            goto done;
        }
        program = default_program;
    }
    if (access(program, X_OK) != 0) {
        (void)fprintf(stderr, "fortytwo-login: cannot execute %s\n", program);
        goto done;
    }
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        (void)fputs("fortytwo-login: terminal input unavailable\n", stderr);
        goto done;
    }

    if (strcmp(options->protocol, FTAP_PROTOCOL_TELNET) == 0) {
        if (!display_telnet_issue(options->mbse_root) ||
            terminal_wait_for_double_escape(
                STDIN_FILENO, STDOUT_FILENO,
                TERMINAL_GATE_DEFAULT_SECONDS) != TERMINAL_GATE_OK) {
            goto done;
        }
    }
    if (!read_line("Login: ", login_name, sizeof(login_name))) {
        (void)fputs("fortytwo-login: terminal input failed\n", stderr);
        goto done;
    }
    registration_requested = ascii_word_is_new(login_name);
    if (registration_requested) {
        secure_wipe(login_name, sizeof(login_name));
        if (!options->registration_enabled) {
            (void)fputs("New user registration is not enabled.\r\n", stderr);
            goto done;
        }
        if (!collect_registration_input(login_name, display_name,
                                        password, password_repeat)) {
            goto done;
        }
    } else if (!read_password("Password: ", password, sizeof(password))) {
        (void)fputs("fortytwo-login: terminal input failed\n", stderr);
        goto done;
    }

    metadata.protocol = options->protocol;
    metadata.source_ip = derive_source_ip(options, source_ip);
    if (options->source_ip != NULL && metadata.source_ip == NULL) {
        (void)fputs("fortytwo-login: source IP is not canonical\n", stderr);
        goto done;
    }
    metadata.tty_device = derive_tty_device(options, tty_device);
    metadata.node_id = options->node_id;
    registration_metadata.protocol = metadata.protocol;
    registration_metadata.source_ip = metadata.source_ip;
    registration_metadata.tty_device = metadata.tty_device;
    registration_metadata.node_id = metadata.node_id;

    if (registration_requested) {
        time_t now = time(NULL);

        if (now <= (time_t)0 || (uint64_t)now > (uint64_t)INT32_MAX ||
            registration_metadata.source_ip == NULL) {
            (void)fputs("Registration metadata is unavailable.\r\n", stderr);
            goto done;
        }
        registration_time = (int64_t)now;
    }

    if (ftap_client_connect(&client, options->socket_path, &error) != 0 ||
        ftap_client_hello(&client, "fortytwo-login",
                          FORTYTWO_LOGIN_VERSION, &error) != 0) {
        print_client_error(&error, NULL);
        goto done;
    }

    if (registration_requested) {
        registration_request.client = &client;
        registration_request.mbse_root = options->mbse_root;
        registration_request.bbs_users_directory = bbs_users_directory;
        registration_request.login_name = login_name;
        registration_request.display_name = display_name;
        registration_request.password = (const uint8_t *)password;
        registration_request.password_length = strlen(password);
        registration_request.metadata = &registration_metadata;
        registration_request.registered_at = registration_time;
        registration_request.legacy_defaults = &legacy_defaults;
        registration_request.legacy_policy = &legacy_policy;

        if (fortytwo_registration_coordinate(
                &registration_request, &registration_result,
                &registration_error) != 0) {
            print_registration_error(&registration_error);
            goto done;
        }
        result = registration_result.terminal;
        (void)fputs("Registration complete. Entering FortyTwo BBS...\r\n",
                    stdout);
        (void)fflush(stdout);
    } else if (ftap_client_authenticate_password(
                   &client, login_name, (const uint8_t *)password,
                   strlen(password), &metadata, &result, &error) != 0) {
        print_client_error(&error, options->protocol);
        goto done;
    }

    secure_wipe(password, sizeof(password));
    secure_wipe(password_repeat, sizeof(password_repeat));
    secure_wipe(login_name, sizeof(login_name));
    secure_wipe(display_name, sizeof(display_name));

    if (ftap_client_move_to_inherited_fd(&client, &error) != 0) {
        print_client_error(&error, NULL);
        (void)ftap_client_session_close(&client, "handoff_failed", NULL);
        goto done;
    }
    if (!sanitize_environment(options->mbse_root)) {
        (void)fputs("fortytwo-login: cannot create safe environment\n",
                    stderr);
        (void)ftap_client_session_close(&client, "environment_error", NULL);
        goto done;
    }

    close_unneeded_descriptors();
    child_argv[0] = (char *)program;
    child_argv[1] = NULL;
    execve(program, child_argv, environ);

    (void)fprintf(stderr, "fortytwo-login: cannot execute %s: %s\n",
                  program, strerror(errno));
    (void)ftap_client_session_close(&client, "exec_failed", NULL);

done:
    secure_wipe(password, sizeof(password));
    secure_wipe(password_repeat, sizeof(password_repeat));
    secure_wipe(login_name, sizeof(login_name));
    secure_wipe(display_name, sizeof(display_name));
    secure_wipe(&result, sizeof(result));
    secure_wipe(&registration_result, sizeof(registration_result));
    secure_wipe(&registration_request, sizeof(registration_request));
    ftap_client_close(&client);
    return exit_status;
}

int
main(int argc, char **argv)
{
    login_options_t options;
    int parse_result = parse_options(argc, argv, &options);

    if (parse_result > 0) {
        return 0;
    }
    if (parse_result < 0) {
        return 2;
    }
    return run_login(&options);
}
