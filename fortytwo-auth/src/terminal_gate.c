/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Telnet presence gate and symbol-based registration challenge.
 */

#include "terminal_gate.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define ESCAPE_BYTE 0x1bU
#define CHALLENGE_RANDOM_WORDS 16U
#define CHALLENGE_INPUT_SIZE 16U
#define MILLISECONDS_PER_SECOND 1000LL

static const char *const symbols[] = {
    "\033[1;33m★\033[0m",
    "\033[1;36m◇\033[0m",
    "\033[1;32m▲\033[0m",
    "\033[1;35m▼\033[0m",
    "\033[1;31m■\033[0m"
};

static int
write_all(int fd, const void *buffer, size_t length)
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
        return -1;
    }
    return 0;
}

static int
write_text(int fd, const char *text)
{
    return write_all(fd, text, strlen(text));
}

static int64_t
monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    if (now.tv_sec > INT64_MAX / MILLISECONDS_PER_SECOND) {
        errno = EOVERFLOW;
        return -1;
    }
    return (int64_t)now.tv_sec * MILLISECONDS_PER_SECOND +
           (int64_t)(now.tv_nsec / 1000000L);
}

static int
remaining_poll_timeout(int64_t deadline_ms, int maximum_ms)
{
    int64_t now = monotonic_milliseconds();
    int64_t remaining;

    if (now < 0) {
        return -1;
    }
    remaining = deadline_ms - now;
    if (remaining <= 0) {
        return 0;
    }
    if (remaining > maximum_ms) {
        remaining = maximum_ms;
    }
    return (int)remaining;
}

static int
set_character_mode(int fd, struct termios *original)
{
    struct termios mode;

    if (tcgetattr(fd, original) != 0) {
        return -1;
    }
    mode = *original;
    mode.c_lflag &= (tcflag_t)~(ICANON | ECHO | ISIG);
    mode.c_cc[VMIN] = 0;
    mode.c_cc[VTIME] = 0;
    return tcsetattr(fd, TCSAFLUSH, &mode);
}

static int
restore_terminal(int fd, const struct termios *original)
{
    return tcsetattr(fd, TCSANOW, original);
}

void
terminal_escape_state_init(terminal_escape_state_t *state)
{
    if (state != NULL) {
        state->consecutive_escapes = 0U;
    }
}

bool
terminal_escape_state_feed(terminal_escape_state_t *state,
                           unsigned char byte)
{
    if (state == NULL) {
        return false;
    }
    if (byte == ESCAPE_BYTE) {
        ++state->consecutive_escapes;
        return state->consecutive_escapes >= 2U;
    }
    state->consecutive_escapes = 0U;
    return false;
}

const char *
terminal_gate_status_name(terminal_gate_status_t status)
{
    switch (status) {
    case TERMINAL_GATE_OK:
        return "ok";
    case TERMINAL_GATE_TIMEOUT:
        return "timeout";
    case TERMINAL_GATE_REJECTED:
        return "rejected";
    case TERMINAL_GATE_IO_ERROR:
        return "io_error";
    case TERMINAL_GATE_TERMINAL_ERROR:
        return "terminal_error";
    case TERMINAL_GATE_RANDOM_ERROR:
        return "random_error";
    default:
        return "unknown";
    }
}

terminal_gate_status_t
terminal_wait_for_double_escape(int input_fd,
                                int output_fd,
                                unsigned int seconds)
{
    struct termios original;
    terminal_escape_state_t state;
    int64_t now;
    int64_t deadline;
    unsigned int last_display = UINT_MAX;
    terminal_gate_status_t status = TERMINAL_GATE_IO_ERROR;

    if (seconds == 0U || !isatty(input_fd)) {
        return TERMINAL_GATE_TERMINAL_ERROR;
    }
    if (set_character_mode(input_fd, &original) != 0) {
        return TERMINAL_GATE_TERMINAL_ERROR;
    }

    now = monotonic_milliseconds();
    if (now < 0 || seconds > (unsigned int)(INT64_MAX / 1000LL) ||
        now > INT64_MAX - (int64_t)seconds * 1000LL) {
        status = TERMINAL_GATE_IO_ERROR;
        goto done;
    }
    deadline = now + (int64_t)seconds * 1000LL;
    terminal_escape_state_init(&state);

    for (;;) {
        struct pollfd descriptor;
        unsigned int display;
        int timeout;
        int poll_result;

        now = monotonic_milliseconds();
        if (now < 0) {
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        if (now >= deadline) {
            status = TERMINAL_GATE_TIMEOUT;
            break;
        }
        display = (unsigned int)((deadline - now + 999LL) / 1000LL);
        if (display != last_display) {
            char line[96];
            int length = snprintf(line, sizeof(line),
                                  "\r\033[KPress ESC twice to continue: %2u",
                                  display);
            if (length < 0 || (size_t)length >= sizeof(line) ||
                write_all(output_fd, line, (size_t)length) != 0) {
                status = TERMINAL_GATE_IO_ERROR;
                break;
            }
            last_display = display;
        }

        timeout = remaining_poll_timeout(deadline, 200);
        if (timeout < 0) {
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.fd = input_fd;
        descriptor.events = POLLIN;
        poll_result = poll(&descriptor, 1U, timeout);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        if (poll_result == 0) {
            continue;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        if ((descriptor.revents & POLLIN) != 0) {
            unsigned char bytes[32];
            ssize_t received = read(input_fd, bytes, sizeof(bytes));
            size_t index;

            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                status = TERMINAL_GATE_IO_ERROR;
                break;
            }
            for (index = 0U; index < (size_t)received; ++index) {
                if (terminal_escape_state_feed(&state, bytes[index])) {
                    status = TERMINAL_GATE_OK;
                    goto done;
                }
            }
        }
    }

done:
    if (restore_terminal(input_fd, &original) != 0 &&
        status == TERMINAL_GATE_OK) {
        status = TERMINAL_GATE_TERMINAL_ERROR;
    }
    if (status == TERMINAL_GATE_OK) {
        (void)write_text(output_fd, "\r\033[K");
    } else if (status == TERMINAL_GATE_TIMEOUT) {
        (void)write_text(output_fd, "\r\033[KConnection timed out.\r\n");
    } else {
        (void)write_text(output_fd, "\r\033[K");
    }
    return status;
}

static terminal_gate_status_t
fill_random_words(uint32_t *words, size_t count)
{
    size_t offset = 0U;
    unsigned char *bytes = (unsigned char *)words;
    size_t length = count * sizeof(*words);

    while (offset < length) {
        ssize_t received = getrandom(bytes + offset, length - offset, 0);

        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        return TERMINAL_GATE_RANDOM_ERROR;
    }
    return TERMINAL_GATE_OK;
}

static uint32_t
bounded_word(uint32_t word, uint32_t minimum, uint32_t maximum)
{
    return minimum + word % (maximum - minimum + 1U);
}

static terminal_gate_status_t
challenge_from_words(registration_challenge_t *challenge,
                     const uint32_t *words,
                     size_t word_count)
{
    size_t order[5] = {0U, 1U, 2U, 3U, 4U};
    size_t index;
    unsigned int template_number;
    int a = 0;
    int b = 0;
    int c = 0;
    int answer = 0;
    int length;
    char question[512];
    const char *first;
    const char *second;
    const char *third;

    if (challenge == NULL || words == NULL || word_count < 8U) {
        return TERMINAL_GATE_RANDOM_ERROR;
    }

    for (index = 4U; index > 0U; --index) {
        size_t selected = words[index] % (index + 1U);
        size_t temporary = order[index];
        order[index] = order[selected];
        order[selected] = temporary;
    }
    first = symbols[order[0]];
    second = symbols[order[1]];
    third = symbols[order[2]];
    template_number = words[6] % 8U;

    switch (template_number) {
    case 0U:
        a = (int)(2U * bounded_word(words[7], 2U, 9U));
        b = (int)bounded_word(words[8], 1U, 9U);
        answer = a / 2 + b;
        length = snprintf(question, sizeof(question),
                          "If %s = %d and %s = %d, add half of %s to %s. What is the result?",
                          first, a, second, b, first, second);
        break;
    case 1U:
        a = (int)bounded_word(words[7], 2U, 9U);
        b = (int)bounded_word(words[8], 2U, 9U);
        c = (int)bounded_word(words[9], 1U, 9U);
        answer = a * b + c;
        length = snprintf(question, sizeof(question),
                          "If %s = %d, %s = %d and %s = %d, what is %s × %s + %s?",
                          first, a, second, b, third, c, first, second, third);
        break;
    case 2U: {
        int divisor = (int)bounded_word(words[7], 2U, 5U);
        int quotient = (int)bounded_word(words[8], 2U, 9U);
        int total = divisor * quotient;

        a = (int)bounded_word(words[9], 1U, (uint32_t)(total - 1));
        b = total - a;
        c = divisor;
        answer = quotient;
        length = snprintf(question, sizeof(question),
                          "If %s = %d, %s = %d and %s = %d, divide the sum of %s and %s by %s. What is the result?",
                          first, a, second, b, third, c, first, second, third);
        break;
    }
    case 3U:
        a = (int)bounded_word(words[7], 5U, 10U);
        b = (int)bounded_word(words[8], 1U, (uint32_t)(a - 1));
        answer = a * a - b * b;
        length = snprintf(question, sizeof(question),
                          "If %s = %d and %s = %d, subtract the square of %s from the square of %s. What is the result?",
                          first, a, second, b, second, first);
        break;
    case 4U:
        a = (int)bounded_word(words[7], 5U, 12U);
        b = (int)bounded_word(words[8], 1U, (uint32_t)(a - 1));
        c = (int)bounded_word(words[9], 2U, 5U);
        answer = (a - b) * c;
        length = snprintf(question, sizeof(question),
                          "If %s = %d, %s = %d and %s = %d, multiply the difference %s - %s by %s. What is the result?",
                          first, a, second, b, third, c, first, second, third);
        break;
    case 5U:
        a = (int)bounded_word(words[7], 1U, 9U);
        b = (int)bounded_word(words[8], 2U, 8U);
        c = (int)bounded_word(words[9], 2U, 8U);
        answer = a + b * c;
        length = snprintf(question, sizeof(question),
                          "If %s = %d, %s = %d and %s = %d, add %s to the product of %s and %s. What is the result?",
                          first, a, second, b, third, c, first, second, third);
        break;
    case 6U:
        a = (int)bounded_word(words[7], 1U, 8U);
        b = (int)(2U * bounded_word(words[8], 1U, 8U));
        answer = 2 * a + b / 2;
        length = snprintf(question, sizeof(question),
                          "If %s = %d and %s = %d, add twice %s to half of %s. What is the result?",
                          first, a, second, b, first, second);
        break;
    default:
        a = (int)bounded_word(words[7], 2U, 9U);
        b = (int)bounded_word(words[8], 2U, 9U);
        c = (int)bounded_word(words[9], 1U,
                              (uint32_t)(a * b - 1));
        answer = a * b - c;
        length = snprintf(question, sizeof(question),
                          "If %s = %d, %s = %d and %s = %d, subtract %s from the product of %s and %s. What is the result?",
                          first, a, second, b, third, c, third, first, second);
        break;
    }

    if (length < 0 || (size_t)length >= sizeof(question)) {
        return TERMINAL_GATE_RANDOM_ERROR;
    }
    length = snprintf(challenge->text, sizeof(challenge->text),
                      "\r\n\033[1;36mRegistration protection\033[0m\r\n"
                      "%s\r\n",
                      question);
    if (length < 0 || (size_t)length >= sizeof(challenge->text)) {
        return TERMINAL_GATE_RANDOM_ERROR;
    }
    challenge->answer = answer;
    return TERMINAL_GATE_OK;
}

terminal_gate_status_t
registration_challenge_generate(registration_challenge_t *challenge)
{
    uint32_t words[CHALLENGE_RANDOM_WORDS];
    terminal_gate_status_t status;

    memset(words, 0, sizeof(words));
#ifdef TERMINAL_GATE_TESTING
    if (getenv("FORTYTWO_TEST_CHALLENGE_FIXED") != NULL) {
        static const uint32_t fixed_words[CHALLENGE_RANDOM_WORDS] = {
            17U, 3U, 29U, 5U, 11U, 7U, 0U, 13U,
            19U, 23U, 31U, 37U, 41U, 43U, 47U, 53U
        };

        memcpy(words, fixed_words, sizeof(words));
        status = challenge_from_words(challenge, words,
                                      CHALLENGE_RANDOM_WORDS);
        memset(words, 0, sizeof(words));
        return status;
    }
#endif
    status = fill_random_words(words, CHALLENGE_RANDOM_WORDS);
    if (status == TERMINAL_GATE_OK) {
        status = challenge_from_words(challenge, words,
                                      CHALLENGE_RANDOM_WORDS);
    }
    memset(words, 0, sizeof(words));
    return status;
}

#ifdef TERMINAL_GATE_TESTING
terminal_gate_status_t
registration_challenge_generate_from_words(registration_challenge_t *challenge,
                                            const uint32_t *words,
                                            size_t word_count)
{
    return challenge_from_words(challenge, words, word_count);
}
#endif

bool
registration_challenge_verify(const registration_challenge_t *challenge,
                              const char *answer_text)
{
    char *end = NULL;
    long value;

    if (challenge == NULL || answer_text == NULL || answer_text[0] == '\0') {
        return false;
    }
    errno = 0;
    value = strtol(answer_text, &end, 10);
    if (errno != 0 || end == answer_text) {
        return false;
    }
    while (*end == ' ' || *end == '\t') {
        ++end;
    }
    return *end == '\0' && value == challenge->answer;
}

static terminal_gate_status_t
read_decimal_until(int input_fd,
                   int output_fd,
                   int64_t deadline,
                   char output[CHALLENGE_INPUT_SIZE])
{
    struct termios original;
    size_t length = 0U;
    terminal_gate_status_t status = TERMINAL_GATE_IO_ERROR;

    memset(output, 0, CHALLENGE_INPUT_SIZE);
    if (set_character_mode(input_fd, &original) != 0) {
        return TERMINAL_GATE_TERMINAL_ERROR;
    }

    for (;;) {
        struct pollfd descriptor;
        int timeout = remaining_poll_timeout(deadline, 250);
        int poll_result;

        if (timeout < 0) {
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        if (timeout == 0) {
            status = TERMINAL_GATE_TIMEOUT;
            break;
        }
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.fd = input_fd;
        descriptor.events = POLLIN;
        poll_result = poll(&descriptor, 1U, timeout);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        if (poll_result == 0) {
            continue;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        if ((descriptor.revents & POLLIN) != 0) {
            unsigned char byte;
            ssize_t received = read(input_fd, &byte, 1U);

            if (received < 0 && errno == EINTR) {
                continue;
            }
            if (received <= 0) {
                status = TERMINAL_GATE_IO_ERROR;
                break;
            }
            if (byte == '\r' || byte == '\n') {
                if (write_text(output_fd, "\r\n") != 0) {
                    status = TERMINAL_GATE_IO_ERROR;
                } else {
                    status = length > 0U ? TERMINAL_GATE_OK
                                         : TERMINAL_GATE_REJECTED;
                }
                break;
            }
            if (byte == 0x08U || byte == 0x7fU) {
                if (length > 0U) {
                    --length;
                    output[length] = '\0';
                    if (write_text(output_fd, "\b \b") != 0) {
                        status = TERMINAL_GATE_IO_ERROR;
                        break;
                    }
                }
                continue;
            }
            if (byte >= (unsigned char)'0' &&
                byte <= (unsigned char)'9' &&
                length + 1U < CHALLENGE_INPUT_SIZE) {
                output[length++] = (char)byte;
                output[length] = '\0';
                if (write_all(output_fd, &byte, 1U) != 0) {
                    status = TERMINAL_GATE_IO_ERROR;
                    break;
                }
            }
        }
    }

    if (restore_terminal(input_fd, &original) != 0 &&
        status == TERMINAL_GATE_OK) {
        status = TERMINAL_GATE_TERMINAL_ERROR;
    }
    return status;
}

terminal_gate_status_t
registration_challenge_run(int input_fd,
                           int output_fd,
                           unsigned int seconds,
                           unsigned int attempts)
{
    registration_challenge_t challenge;
    terminal_gate_status_t status;
    int64_t now;
    int64_t deadline;
    unsigned int attempt;

    if (seconds == 0U || attempts == 0U || !isatty(input_fd)) {
        return TERMINAL_GATE_TERMINAL_ERROR;
    }
    memset(&challenge, 0, sizeof(challenge));
    status = registration_challenge_generate(&challenge);
    if (status != TERMINAL_GATE_OK) {
        return status;
    }
    if (write_text(output_fd, challenge.text) != 0) {
        return TERMINAL_GATE_IO_ERROR;
    }
    now = monotonic_milliseconds();
    if (now < 0 || seconds > (unsigned int)(INT64_MAX / 1000LL) ||
        now > INT64_MAX - (int64_t)seconds * 1000LL) {
        return TERMINAL_GATE_IO_ERROR;
    }
    deadline = now + (int64_t)seconds * 1000LL;

    for (attempt = 0U; attempt < attempts; ++attempt) {
        char answer[CHALLENGE_INPUT_SIZE];

        if (write_text(output_fd, "Answer: ") != 0) {
            status = TERMINAL_GATE_IO_ERROR;
            break;
        }
        status = read_decimal_until(input_fd, output_fd, deadline, answer);
        if (status == TERMINAL_GATE_TIMEOUT) {
            (void)write_text(output_fd, "Time expired.\r\n");
            break;
        }
        if (status != TERMINAL_GATE_OK) {
            if (status == TERMINAL_GATE_REJECTED && attempt + 1U < attempts) {
                (void)write_text(output_fd, "Please enter a number.\r\n");
                continue;
            }
            break;
        }
        if (registration_challenge_verify(&challenge, answer)) {
            (void)write_text(output_fd, "Correct.\r\n\r\n");
            status = TERMINAL_GATE_OK;
            break;
        }
        if (attempt + 1U < attempts) {
            (void)write_text(output_fd, "Not correct. Try once more.\r\n");
        } else {
            (void)write_text(output_fd, "Registration denied.\r\n");
            status = TERMINAL_GATE_REJECTED;
        }
    }
    memset(&challenge, 0, sizeof(challenge));
    return status;
}
