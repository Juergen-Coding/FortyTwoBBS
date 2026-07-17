/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Telnet presence gate and registration challenge helpers.
 */

#ifndef FORTYTWO_TERMINAL_GATE_H
#define FORTYTWO_TERMINAL_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TERMINAL_GATE_DEFAULT_SECONDS 15U
#define REGISTRATION_CHALLENGE_DEFAULT_SECONDS 180U
#define REGISTRATION_CHALLENGE_DEFAULT_ATTEMPTS 3U
#define REGISTRATION_CHALLENGE_TEXT_SIZE 768U

typedef enum terminal_gate_status {
    TERMINAL_GATE_OK = 0,
    TERMINAL_GATE_TIMEOUT,
    TERMINAL_GATE_REJECTED,
    TERMINAL_GATE_IO_ERROR,
    TERMINAL_GATE_TERMINAL_ERROR,
    TERMINAL_GATE_RANDOM_ERROR
} terminal_gate_status_t;

typedef struct terminal_escape_state {
    unsigned int consecutive_escapes;
} terminal_escape_state_t;

typedef struct registration_challenge {
    char text[REGISTRATION_CHALLENGE_TEXT_SIZE];
    int answer;
} registration_challenge_t;

void terminal_escape_state_init(terminal_escape_state_t *state);
bool terminal_escape_state_feed(terminal_escape_state_t *state,
                                unsigned char byte);
const char *terminal_gate_status_name(terminal_gate_status_t status);

terminal_gate_status_t terminal_wait_for_double_escape(int input_fd,
                                                        int output_fd,
                                                        unsigned int seconds);

terminal_gate_status_t registration_challenge_generate(
    registration_challenge_t *challenge);
bool registration_challenge_verify(const registration_challenge_t *challenge,
                                   const char *answer_text);
terminal_gate_status_t registration_challenge_run(int input_fd,
                                                   int output_fd,
                                                   unsigned int seconds,
                                                   unsigned int attempts);

#ifdef TERMINAL_GATE_TESTING
terminal_gate_status_t registration_challenge_generate_from_words(
    registration_challenge_t *challenge,
    const uint32_t *words,
    size_t word_count);
#endif

#endif /* FORTYTWO_TERMINAL_GATE_H */
