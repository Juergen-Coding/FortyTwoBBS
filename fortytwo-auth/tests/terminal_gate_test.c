/* SPDX-License-Identifier: GPL-2.0-only */

#include "terminal_gate.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static void
test_escape_parser(void)
{
    terminal_escape_state_t state;

    terminal_escape_state_init(&state);
    assert(!terminal_escape_state_feed(&state, 0x1bU));
    assert(terminal_escape_state_feed(&state, 0x1bU));

    terminal_escape_state_init(&state);
    assert(!terminal_escape_state_feed(&state, 0x1bU));
    assert(!terminal_escape_state_feed(&state, (unsigned char)'['));
    assert(!terminal_escape_state_feed(&state, (unsigned char)'A'));
    assert(!terminal_escape_state_feed(&state, 0x1bU));
    assert(terminal_escape_state_feed(&state, 0x1bU));
}

static void
wait_for_prompt(int master_fd)
{
    char output[256];
    size_t length = 0U;

    memset(output, 0, sizeof(output));
    while (strstr(output, "Press ESC twice") == NULL) {
        struct pollfd descriptor;
        ssize_t received;

        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.fd = master_fd;
        descriptor.events = POLLIN;
        assert(poll(&descriptor, 1U, 2000) == 1);
        received = read(master_fd, output + length,
                        sizeof(output) - length - 1U);
        assert(received > 0);
        length += (size_t)received;
        output[length] = '\0';
        assert(length + 1U < sizeof(output));
    }
}

static void
test_escape_gate_pty(void)
{
    int master_fd;
    int slave_fd;
    struct termios before;
    struct termios after;
    pid_t child;
    int wait_status;
    static const unsigned char input[] = {
        0x1bU, (unsigned char)'[', (unsigned char)'A', 0x1bU, 0x1bU
    };

    assert(openpty(&master_fd, &slave_fd, NULL, NULL, NULL) == 0);
    assert(tcgetattr(slave_fd, &before) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        terminal_gate_status_t status;

        (void)close(master_fd);
        status = terminal_wait_for_double_escape(slave_fd, slave_fd, 2U);
        (void)close(slave_fd);
        _exit(status == TERMINAL_GATE_OK ? 0 : 1);
    }

    wait_for_prompt(master_fd);
    assert(write(master_fd, input, sizeof(input)) == (ssize_t)sizeof(input));
    assert(waitpid(child, &wait_status, 0) == child);
    assert(WIFEXITED(wait_status));
    assert(WEXITSTATUS(wait_status) == 0);
    assert(tcgetattr(slave_fd, &after) == 0);
    assert((after.c_lflag & (ICANON | ECHO | ISIG)) ==
           (before.c_lflag & (ICANON | ECHO | ISIG)));
    assert(close(slave_fd) == 0);
    assert(close(master_fd) == 0);
}

static void
test_number_sequence_challenge(void)
{
    uint32_t words[16] = {
        17U, 3U, 29U, 5U, 11U, 7U, 2U, 1U,
        19U, 23U, 31U, 37U, 41U, 43U, 47U, 53U
    };
    registration_challenge_t challenge;
    char answer[32];

    memset(&challenge, 0, sizeof(challenge));
    assert(registration_challenge_generate_from_words(
               &challenge, words, sizeof(words) / sizeof(words[0])) ==
           TERMINAL_GATE_OK);

    assert(strstr(
               challenge.text,
               "Ergaenze die Zahlenreihe / Complete the sequence:") != NULL);
    assert(strstr(
               challenge.text,
               "3, 6, 10, 15, 21, 28, ?") != NULL);
    assert(challenge.answer == 36);

    assert(snprintf(answer, sizeof(answer), "%d", challenge.answer) > 0);
    assert(registration_challenge_verify(&challenge, answer));
    assert(registration_challenge_verify(&challenge, "36"));
    assert(registration_challenge_verify(&challenge, "36  "));
    assert(!registration_challenge_verify(&challenge, "35"));
    assert(!registration_challenge_verify(&challenge, "36x"));
    assert(!registration_challenge_verify(&challenge, ""));
}

static void
test_status_names(void)
{
    assert(strcmp(terminal_gate_status_name(TERMINAL_GATE_OK), "ok") == 0);
    assert(strcmp(terminal_gate_status_name(TERMINAL_GATE_TIMEOUT),
                  "timeout") == 0);
    assert(strcmp(terminal_gate_status_name(TERMINAL_GATE_REJECTED),
                  "rejected") == 0);
}

int
main(void)
{
    test_escape_parser();
    test_escape_gate_pty();
    test_number_sequence_challenge();
    test_status_names();
    puts("terminal gate and registration challenge tests: OK");
    return 0;
}
