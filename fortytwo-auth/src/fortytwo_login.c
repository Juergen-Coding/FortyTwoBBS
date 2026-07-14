/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Local terminal login adapter for fortytwo-authd.
 */

#include "ftap_client.h"
#include "ftap_protocol.h"

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
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <termios.h>
#include <unistd.h>

#define FORTYTWO_LOGIN_VERSION "0.1.0"
#define LOGIN_LINE_BUFFER_SIZE (FTAP_LOGIN_NAME_MAX + 2U)
#define PASSWORD_BUFFER_SIZE (FTAP_PASSWORD_MAX + 2U)

typedef struct login_options {
    const char *socket_path;
    const char *protocol;
    const char *source_ip;
    const char *tty_device;
    const char *node_id;
    const char *mbse_root;
    const char *program;
    uint32_t timeout_ms;
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
    if (options->program != NULL && options->program[0] != '/') {
        (void)fprintf(stderr,
                      "fortytwo-login: program path must be absolute\n");
        return -1;
    }
    return 0;
}

static bool
read_line(const char *prompt, char *buffer, size_t buffer_size)
{
    size_t length;

    (void)fputs(prompt, stdout);
    (void)fflush(stdout);
    if (fgets(buffer, (int)buffer_size, stdin) == NULL) {
        return false;
    }

    length = strcspn(buffer, "\r\n");
    if (buffer[length] == '\0' && !feof(stdin)) {
        int character;
        do {
            character = fgetc(stdin);
        } while (character != '\n' && character != EOF);
        return false;
    }
    buffer[length] = '\0';
    return length > 0U;
}

/* Disable echo only while the password bytes are read from the terminal. */
static bool
read_password(char *buffer, size_t buffer_size)
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
            success = read_line("Password: ", buffer, buffer_size);
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
print_client_error(const ftap_client_error_t *error)
{
    if (error != NULL &&
        (error->protocol_error == FTAP_ERR_INVALID_CREDENTIALS ||
         error->protocol_error == FTAP_ERR_ACCOUNT_UNAVAILABLE)) {
        (void)fputs("Login failed.\r\n", stderr);
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

/* Authenticate once, then replace the adapter while preserving only FD 3. */
static int
run_login(const login_options_t *options)
{
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_password_metadata_t metadata;
    ftap_terminal_context_t result;
    char login_name[LOGIN_LINE_BUFFER_SIZE];
    char password[PASSWORD_BUFFER_SIZE];
    char source_ip[INET6_ADDRSTRLEN];
    char tty_device[FTAP_TTY_DEVICE_MAX + 1U];
    char default_program[PATH_MAX];
    const char *program = options->program;
    char *child_argv[2];
    int exit_status = 1;

    memset(login_name, 0, sizeof(login_name));
    memset(password, 0, sizeof(password));
    memset(&metadata, 0, sizeof(metadata));
    memset(&result, 0, sizeof(result));
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
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) ||
        !read_line("Login: ", login_name, sizeof(login_name)) ||
        !read_password(password, sizeof(password))) {
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

    if (ftap_client_connect(&client, options->socket_path, &error) != 0 ||
        ftap_client_hello(&client, "fortytwo-login",
                          FORTYTWO_LOGIN_VERSION, &error) != 0 ||
        ftap_client_authenticate_password(
            &client, login_name, (const uint8_t *)password,
            strlen(password), &metadata, &result, &error) != 0) {
        print_client_error(&error);
        goto done;
    }
    secure_wipe(password, sizeof(password));
    secure_wipe(login_name, sizeof(login_name));

    if (ftap_client_move_to_inherited_fd(&client, &error) != 0) {
        print_client_error(&error);
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
    secure_wipe(login_name, sizeof(login_name));
    secure_wipe(&result, sizeof(result));
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
