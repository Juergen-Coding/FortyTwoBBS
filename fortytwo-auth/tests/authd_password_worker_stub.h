/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Deterministic password verifier used by worker-pool tests.
 */

#ifndef FORTYTWO_AUTHD_PASSWORD_WORKER_STUB_H
#define FORTYTWO_AUTHD_PASSWORD_WORKER_STUB_H

#include <stddef.h>

void authd_password_worker_stub_reset(unsigned int delay_ms);
size_t authd_password_worker_stub_call_count(void);
size_t authd_password_worker_stub_generate_call_count(void);
size_t authd_password_worker_stub_max_parallel(void);

#endif /* FORTYTWO_AUTHD_PASSWORD_WORKER_STUB_H */
