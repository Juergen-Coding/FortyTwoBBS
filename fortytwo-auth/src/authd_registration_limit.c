/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_registration_limit.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

/* Install conservative defaults without enabling registration itself. */
void
authd_registration_limit_policy_defaults(
    authd_registration_limit_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }

    policy->attempts = AUTHD_REGISTRATION_DEFAULT_IP_ATTEMPTS;
    policy->window_seconds =
        AUTHD_REGISTRATION_DEFAULT_IP_WINDOW_SECONDS;
}

/* Keep the limiter finite and reject policies that disable protection. */
bool
authd_registration_limit_policy_is_valid(
    const authd_registration_limit_policy_t *policy)
{
    return policy != NULL &&
           policy->attempts >= AUTHD_REGISTRATION_MIN_IP_ATTEMPTS &&
           policy->attempts <= AUTHD_REGISTRATION_MAX_IP_ATTEMPTS &&
           policy->window_seconds >=
               AUTHD_REGISTRATION_MIN_IP_WINDOW_SECONDS &&
           policy->window_seconds <=
               AUTHD_REGISTRATION_MAX_IP_WINDOW_SECONDS;
}

bool
authd_registration_limiter_init(
    authd_registration_limiter_t *limiter,
    const authd_registration_limit_policy_t *policy)
{
    if (limiter == NULL ||
        !authd_registration_limit_policy_is_valid(policy)) {
        return false;
    }

    memset(limiter, 0, sizeof(*limiter));
    limiter->policy = *policy;
    return true;
}

void
authd_registration_limiter_clear(authd_registration_limiter_t *limiter)
{
    if (limiter != NULL) {
        memset(limiter, 0, sizeof(*limiter));
    }
}

static bool
parse_canonical_ip(const char *source_ip,
                   int *address_family,
                   unsigned char address[AUTHD_REGISTRATION_ADDRESS_BYTES])
{
    struct in_addr address4;
    struct in6_addr address6;
    char canonical[INET6_ADDRSTRLEN];

    if (source_ip == NULL || source_ip[0] == '\0' ||
        address_family == NULL || address == NULL) {
        return false;
    }

    memset(address, 0, AUTHD_REGISTRATION_ADDRESS_BYTES);
    if (inet_pton(AF_INET, source_ip, &address4) == 1) {
        if (inet_ntop(AF_INET, &address4, canonical, sizeof(canonical)) == NULL ||
            strcmp(source_ip, canonical) != 0) {
            return false;
        }
        *address_family = AF_INET;
        memcpy(address, &address4, sizeof(address4));
        return true;
    }

    if (inet_pton(AF_INET6, source_ip, &address6) == 1) {
        if (inet_ntop(AF_INET6, &address6, canonical, sizeof(canonical)) == NULL ||
            strcmp(source_ip, canonical) != 0) {
            return false;
        }
        *address_family = AF_INET6;
        memcpy(address, &address6, sizeof(address6));
        return true;
    }

    return false;
}

static bool
entry_is_expired(const authd_registration_limit_entry_t *entry,
                 uint64_t now_seconds,
                 uint32_t window_seconds)
{
    if (entry == NULL || !entry->in_use) {
        return false;
    }

    if (now_seconds < entry->window_started_seconds) {
        return true;
    }

    return now_seconds - entry->window_started_seconds >= window_seconds;
}

static uint32_t
entry_retry_after(const authd_registration_limit_entry_t *entry,
                  uint64_t now_seconds,
                  uint32_t window_seconds)
{
    uint64_t elapsed;
    uint64_t remaining;

    if (entry == NULL || now_seconds < entry->window_started_seconds) {
        return UINT32_C(1);
    }

    elapsed = now_seconds - entry->window_started_seconds;
    if (elapsed >= window_seconds) {
        return UINT32_C(1);
    }

    remaining = (uint64_t)window_seconds - elapsed;
    if (remaining == 0U) {
        return UINT32_C(1);
    }
    if (remaining > UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)remaining;
}

/*
 * Record one Begin attempt. Expired entries are reclaimed first; when the
 * fixed table is full, unknown addresses fail closed instead of evicting an
 * active counter and weakening the limit.
 */
authd_registration_limit_result_t
authd_registration_limiter_record(
    authd_registration_limiter_t *limiter,
    const char *source_ip,
    uint64_t now_seconds,
    uint32_t *retry_after_seconds)
{
    unsigned char address[AUTHD_REGISTRATION_ADDRESS_BYTES];
    int address_family;
    authd_registration_limit_entry_t *matching = NULL;
    authd_registration_limit_entry_t *free_entry = NULL;
    uint32_t earliest_retry = UINT32_MAX;
    size_t index;

    if (retry_after_seconds != NULL) {
        *retry_after_seconds = 0U;
    }
    if (limiter == NULL ||
        !authd_registration_limit_policy_is_valid(&limiter->policy) ||
        !parse_canonical_ip(source_ip, &address_family, address)) {
        return AUTHD_REGISTRATION_LIMIT_INVALID_ARGUMENT;
    }

    for (index = 0U; index < AUTHD_REGISTRATION_IP_LIMIT_CAPACITY; ++index) {
        authd_registration_limit_entry_t *entry = &limiter->entries[index];

        if (entry_is_expired(entry, now_seconds,
                             limiter->policy.window_seconds)) {
            memset(entry, 0, sizeof(*entry));
        }
        if (!entry->in_use) {
            if (free_entry == NULL) {
                free_entry = entry;
            }
            continue;
        }
        if (entry->address_family == address_family &&
            memcmp(entry->address, address, sizeof(entry->address)) == 0) {
            matching = entry;
            break;
        }
        {
            uint32_t retry = entry_retry_after(
                entry, now_seconds, limiter->policy.window_seconds);
            if (retry < earliest_retry) {
                earliest_retry = retry;
            }
        }
    }

    if (matching != NULL) {
        if (matching->attempts >= limiter->policy.attempts) {
            if (retry_after_seconds != NULL) {
                *retry_after_seconds = entry_retry_after(
                    matching, now_seconds, limiter->policy.window_seconds);
            }
            return AUTHD_REGISTRATION_LIMIT_RATE_LIMITED;
        }
        matching->attempts += 1U;
        return AUTHD_REGISTRATION_LIMIT_ALLOWED;
    }

    if (free_entry == NULL) {
        if (retry_after_seconds != NULL) {
            *retry_after_seconds = earliest_retry != UINT32_MAX
                ? earliest_retry : UINT32_C(1);
        }
        return AUTHD_REGISTRATION_LIMIT_CAPACITY;
    }

    free_entry->in_use = true;
    free_entry->address_family = address_family;
    memcpy(free_entry->address, address, sizeof(free_entry->address));
    free_entry->attempts = 1U;
    free_entry->window_started_seconds = now_seconds;
    return AUTHD_REGISTRATION_LIMIT_ALLOWED;
}
