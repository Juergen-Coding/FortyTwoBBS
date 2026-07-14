/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_worker_pool.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

typedef struct authd_worker_job {
    uint64_t job_id;
    authd_worker_token_t token;
    char encoded_hash[AUTHD_WORKER_HASH_MAX_BYTES + 1U];
    char password[AUTHD_PASSWORD_MAX_BUFFER_BYTES];
    size_t password_length;
    authd_password_result_t password_result;
    bool needs_rehash;
    struct authd_worker_job *next;
} authd_worker_job_t;

struct authd_worker_pool {
    authd_password_policy_t password_policy;
    pthread_mutex_t mutex;
    pthread_cond_t pending_condition;
    pthread_t *threads;
    size_t thread_count;
    size_t threads_started;
    size_t capacity;
    size_t outstanding;
    uint64_t next_job_id;
    authd_worker_job_t *pending_head;
    authd_worker_job_t *pending_tail;
    authd_worker_job_t *completed_head;
    authd_worker_job_t *completed_tail;
    int completion_fd;
    bool mutex_initialized;
    bool condition_initialized;
    bool stopping;
};

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

/* Remove the first job from a singly linked FIFO queue. */
static authd_worker_job_t *
queue_pop(authd_worker_job_t **head, authd_worker_job_t **tail)
{
    authd_worker_job_t *job;

    if (head == NULL || tail == NULL || *head == NULL) {
        return NULL;
    }

    job = *head;
    *head = job->next;
    if (*head == NULL) {
        *tail = NULL;
    }
    job->next = NULL;
    return job;
}

/* Append a job while preserving submission or completion order. */
static void
queue_push(authd_worker_job_t **head,
           authd_worker_job_t **tail,
           authd_worker_job_t *job)
{
    if (head == NULL || tail == NULL || job == NULL) {
        return;
    }

    job->next = NULL;
    if (*tail == NULL) {
        *head = job;
    } else {
        (*tail)->next = job;
    }
    *tail = job;
}

/* Wipe every password byte before a job allocation leaves the process. */
static void
job_destroy(authd_worker_job_t *job)
{
    if (job == NULL) {
        return;
    }

    authd_password_wipe(job->password, sizeof(job->password));
    authd_password_wipe(job->encoded_hash, sizeof(job->encoded_hash));
    authd_password_wipe(job, sizeof(*job));
    free(job);
}

/* Notify poll() once for every completed job. eventfd uses a 64-bit counter. */
static int
completion_notify(int completion_fd)
{
    uint64_t value = UINT64_C(1);
    ssize_t written;

    do {
        written = write(completion_fd, &value, sizeof(value));
    } while (written < 0 && errno == EINTR);

    return written == (ssize_t)sizeof(value) ? 0 : -1;
}

/* Consume one readiness token before removing one completed job. */
static bool
completion_consume(int completion_fd)
{
    uint64_t value;
    ssize_t received;

    do {
        received = read(completion_fd, &value, sizeof(value));
    } while (received < 0 && errno == EINTR);

    return received == (ssize_t)sizeof(value);
}

/*
 * Workers remove jobs under the mutex, perform Argon2id without the mutex,
 * then return only value data to the completion queue.
 */
static void *
worker_main(void *argument)
{
    authd_worker_pool_t *pool = argument;

    for (;;) {
        authd_worker_job_t *job;
        bool discard;

        (void)pthread_mutex_lock(&pool->mutex);
        while (!pool->stopping && pool->pending_head == NULL) {
            (void)pthread_cond_wait(&pool->pending_condition, &pool->mutex);
        }
        if (pool->stopping) {
            (void)pthread_mutex_unlock(&pool->mutex);
            break;
        }
        job = queue_pop(&pool->pending_head, &pool->pending_tail);
        (void)pthread_mutex_unlock(&pool->mutex);

        if (job == NULL) {
            continue;
        }

        job->password_result = authd_password_verify(
            &pool->password_policy,
            job->encoded_hash,
            job->password,
            job->password_length,
            sizeof(job->password),
            &job->needs_rehash);

        (void)pthread_mutex_lock(&pool->mutex);
        discard = pool->stopping;
        if (discard) {
            if (pool->outstanding > 0U) {
                --pool->outstanding;
            }
        } else {
            queue_push(&pool->completed_head, &pool->completed_tail, job);
        }
        (void)pthread_mutex_unlock(&pool->mutex);

        if (discard) {
            job_destroy(job);
            continue;
        }

        /*
         * The outstanding limit is at most 64, so the eventfd counter cannot
         * overflow. A notification failure therefore indicates process-level
         * descriptor corruption; the completion remains bounded in memory.
         */
        if (completion_notify(pool->completion_fd) != 0) {
            (void)pthread_mutex_lock(&pool->mutex);
            pool->stopping = true;
            (void)pthread_cond_broadcast(&pool->pending_condition);
            (void)pthread_mutex_unlock(&pool->mutex);
            break;
        }
    }

    return NULL;
}

/* Release partially initialized resources after a create failure. */
static void
pool_cleanup_partial(authd_worker_pool_t *pool)
{
    size_t index;

    if (pool == NULL) {
        return;
    }

    if (pool->mutex_initialized) {
        (void)pthread_mutex_lock(&pool->mutex);
        pool->stopping = true;
        if (pool->condition_initialized) {
            (void)pthread_cond_broadcast(&pool->pending_condition);
        }
        (void)pthread_mutex_unlock(&pool->mutex);
    }

    if (pool->threads != NULL) {
        for (index = 0U; index < pool->threads_started; ++index) {
            (void)pthread_join(pool->threads[index], NULL);
        }
    }
    if (pool->completion_fd >= 0) {
        (void)close(pool->completion_fd);
    }
    if (pool->condition_initialized) {
        (void)pthread_cond_destroy(&pool->pending_condition);
    }
    if (pool->mutex_initialized) {
        (void)pthread_mutex_destroy(&pool->mutex);
    }
    free(pool->threads);
    authd_password_wipe(pool, sizeof(*pool));
    free(pool);
}

int
authd_worker_pool_create(const authd_password_policy_t *password_policy,
                         size_t worker_count,
                         size_t capacity,
                         authd_worker_pool_t **pool,
                         char *error,
                         size_t error_size)
{
    authd_worker_pool_t *created;
    size_t index;
    int pthread_result;

    if (pool != NULL) {
        *pool = NULL;
    }
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }

    if (pool == NULL || !authd_password_policy_is_valid(password_policy) ||
        worker_count < AUTHD_WORKER_MIN_THREADS ||
        worker_count > AUTHD_WORKER_MAX_THREADS ||
        capacity < AUTHD_WORKER_MIN_CAPACITY ||
        capacity > AUTHD_WORKER_MAX_CAPACITY ||
        capacity < worker_count) {
        set_error(error, error_size,
                  "worker configuration requires 1..%u threads and a "
                  "capacity between the thread count and %u",
                  AUTHD_WORKER_MAX_THREADS, AUTHD_WORKER_MAX_CAPACITY);
        return -1;
    }

    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        set_error(error, error_size, "out of memory creating worker pool");
        return -1;
    }
    created->completion_fd = -1;
    created->password_policy = *password_policy;
    created->thread_count = worker_count;
    created->capacity = capacity;
    created->next_job_id = UINT64_C(1);

    created->threads = calloc(worker_count, sizeof(*created->threads));
    if (created->threads == NULL) {
        set_error(error, error_size, "out of memory creating worker threads");
        pool_cleanup_partial(created);
        return -1;
    }

    pthread_result = pthread_mutex_init(&created->mutex, NULL);
    if (pthread_result != 0) {
        set_error(error, error_size, "pthread_mutex_init failed: %s",
                  strerror(pthread_result));
        pool_cleanup_partial(created);
        return -1;
    }
    created->mutex_initialized = true;

    pthread_result = pthread_cond_init(&created->pending_condition, NULL);
    if (pthread_result != 0) {
        set_error(error, error_size, "pthread_cond_init failed: %s",
                  strerror(pthread_result));
        pool_cleanup_partial(created);
        return -1;
    }
    created->condition_initialized = true;

    created->completion_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK |
                                           EFD_SEMAPHORE);
    if (created->completion_fd < 0) {
        set_error(error, error_size, "eventfd failed: %s", strerror(errno));
        pool_cleanup_partial(created);
        return -1;
    }

    /* Start all workers before exposing the pool to the caller. */
    for (index = 0U; index < worker_count; ++index) {
        pthread_result = pthread_create(&created->threads[index], NULL,
                                        worker_main, created);
        if (pthread_result != 0) {
            set_error(error, error_size, "pthread_create failed: %s",
                      strerror(pthread_result));
            pool_cleanup_partial(created);
            return -1;
        }
        ++created->threads_started;
    }

    *pool = created;
    return 0;
}

int
authd_worker_pool_completion_fd(const authd_worker_pool_t *pool)
{
    return pool != NULL ? pool->completion_fd : -1;
}

/* Allocate a monotonically increasing nonzero identifier under the mutex. */
static uint64_t
next_job_id_locked(authd_worker_pool_t *pool)
{
    uint64_t identifier = pool->next_job_id;

    ++pool->next_job_id;
    if (pool->next_job_id == UINT64_C(0)) {
        pool->next_job_id = UINT64_C(1);
    }
    return identifier;
}

authd_worker_submit_result_t
authd_worker_pool_submit(authd_worker_pool_t *pool,
                         const authd_worker_token_t *token,
                         const char *encoded_hash,
                         char *password,
                         size_t password_length,
                         size_t password_capacity,
                         uint64_t *job_id)
{
    authd_worker_job_t *job = NULL;
    authd_worker_submit_result_t result = AUTHD_WORKER_SUBMIT_INVALID;
    size_t hash_length;

    if (job_id != NULL) {
        *job_id = UINT64_C(0);
    }

    if (pool == NULL || token == NULL || encoded_hash == NULL ||
        password == NULL || password_length == 0U ||
        password_length > AUTHD_PASSWORD_MAX_BYTES ||
        password_capacity < password_length ||
        password_capacity > AUTHD_PASSWORD_MAX_BUFFER_BYTES ||
        job_id == NULL) {
        goto finished;
    }

    hash_length = strnlen(encoded_hash, AUTHD_WORKER_HASH_MAX_BYTES + 1U);
    if (hash_length == 0U || hash_length > AUTHD_WORKER_HASH_MAX_BYTES) {
        goto finished;
    }

    job = calloc(1U, sizeof(*job));
    if (job == NULL) {
        result = AUTHD_WORKER_SUBMIT_INTERNAL_ERROR;
        goto finished;
    }
    job->token = *token;
    job->password_length = password_length;
    memcpy(job->encoded_hash, encoded_hash, hash_length + 1U);
    memcpy(job->password, password, password_length);

    (void)pthread_mutex_lock(&pool->mutex);
    if (pool->stopping) {
        result = AUTHD_WORKER_SUBMIT_STOPPING;
    } else if (pool->outstanding >= pool->capacity) {
        result = AUTHD_WORKER_SUBMIT_FULL;
    } else {
        job->job_id = next_job_id_locked(pool);
        queue_push(&pool->pending_head, &pool->pending_tail, job);
        ++pool->outstanding;
        *job_id = job->job_id;
        job = NULL;
        result = AUTHD_WORKER_SUBMIT_OK;
        (void)pthread_cond_signal(&pool->pending_condition);
    }
    (void)pthread_mutex_unlock(&pool->mutex);

finished:
    /* The caller never retains a password after attempting submission. */
    if (password != NULL && password_capacity > 0U &&
        password_capacity <= AUTHD_PASSWORD_MAX_BUFFER_BYTES) {
        authd_password_wipe(password, password_capacity);
    }
    job_destroy(job);
    return result;
}

bool
authd_worker_pool_take_completion(authd_worker_pool_t *pool,
                                  authd_worker_completion_t *completion)
{
    authd_worker_job_t *job;

    if (pool == NULL || completion == NULL ||
        !completion_consume(pool->completion_fd)) {
        return false;
    }

    (void)pthread_mutex_lock(&pool->mutex);
    job = queue_pop(&pool->completed_head, &pool->completed_tail);
    if (job != NULL && pool->outstanding > 0U) {
        --pool->outstanding;
    }
    (void)pthread_mutex_unlock(&pool->mutex);

    if (job == NULL) {
        return false;
    }

    memset(completion, 0, sizeof(*completion));
    completion->job_id = job->job_id;
    completion->token = job->token;
    completion->password_result = job->password_result;
    completion->needs_rehash = job->needs_rehash;
    job_destroy(job);
    return true;
}

size_t
authd_worker_pool_outstanding(const authd_worker_pool_t *pool)
{
    size_t outstanding;
    authd_worker_pool_t *mutable_pool;

    if (pool == NULL) {
        return 0U;
    }

    mutable_pool = (authd_worker_pool_t *)pool;
    (void)pthread_mutex_lock(&mutable_pool->mutex);
    outstanding = mutable_pool->outstanding;
    (void)pthread_mutex_unlock(&mutable_pool->mutex);
    return outstanding;
}

void
authd_worker_pool_destroy(authd_worker_pool_t *pool)
{
    authd_worker_job_t *pending;
    authd_worker_job_t *completed;
    size_t index;

    if (pool == NULL) {
        return;
    }

    /* Stop queue intake and detach jobs that have not started yet. */
    (void)pthread_mutex_lock(&pool->mutex);
    pool->stopping = true;
    pending = pool->pending_head;
    pool->pending_head = NULL;
    pool->pending_tail = NULL;
    for (authd_worker_job_t *job = pending; job != NULL; job = job->next) {
        if (pool->outstanding > 0U) {
            --pool->outstanding;
        }
    }
    (void)pthread_cond_broadcast(&pool->pending_condition);
    (void)pthread_mutex_unlock(&pool->mutex);

    while (pending != NULL) {
        authd_worker_job_t *next = pending->next;
        job_destroy(pending);
        pending = next;
    }

    /* Running Argon2id calls cannot be cancelled safely; join them. */
    for (index = 0U; index < pool->threads_started; ++index) {
        (void)pthread_join(pool->threads[index], NULL);
    }

    /* Discard completions that the event loop did not consume before shutdown. */
    (void)pthread_mutex_lock(&pool->mutex);
    completed = pool->completed_head;
    pool->completed_head = NULL;
    pool->completed_tail = NULL;
    pool->outstanding = 0U;
    (void)pthread_mutex_unlock(&pool->mutex);

    while (completed != NULL) {
        authd_worker_job_t *next = completed->next;
        job_destroy(completed);
        completed = next;
    }

    (void)close(pool->completion_fd);
    (void)pthread_cond_destroy(&pool->pending_condition);
    (void)pthread_mutex_destroy(&pool->mutex);
    free(pool->threads);
    authd_password_wipe(pool, sizeof(*pool));
    free(pool);
}

const char *
authd_worker_submit_result_name(authd_worker_submit_result_t result)
{
    switch (result) {
    case AUTHD_WORKER_SUBMIT_OK:
        return "ok";
    case AUTHD_WORKER_SUBMIT_FULL:
        return "full";
    case AUTHD_WORKER_SUBMIT_STOPPING:
        return "stopping";
    case AUTHD_WORKER_SUBMIT_INVALID:
        return "invalid";
    case AUTHD_WORKER_SUBMIT_INTERNAL_ERROR:
        return "internal_error";
    default:
        return "unknown";
    }
}
