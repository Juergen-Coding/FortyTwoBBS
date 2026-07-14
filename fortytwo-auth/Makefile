CC ?= cc
PKG_CONFIG ?= pkg-config

LIBPQ_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpq 2>/dev/null)
LIBPQ_LIBS := $(shell $(PKG_CONFIG) --libs libpq 2>/dev/null)
SODIUM_CFLAGS := $(shell $(PKG_CONFIG) --cflags libsodium 2>/dev/null)
SODIUM_LIBS := $(shell $(PKG_CONFIG) --libs libsodium 2>/dev/null)
THREAD_FLAGS := -pthread

CPPFLAGS := -D_GNU_SOURCE -Iinclude $(LIBPQ_CFLAGS) $(SODIUM_CFLAGS)
LIBPQ_WRAP_FLAGS := \
	-Wl,--wrap=PQconnectdbParams \
	-Wl,--wrap=PQsetNoticeProcessor \
	-Wl,--wrap=PQstatus \
	-Wl,--wrap=PQprotocolVersion \
	-Wl,--wrap=PQconnectionUsedPassword \
	-Wl,--wrap=PQsetClientEncoding \
	-Wl,--wrap=PQexec \
	-Wl,--wrap=PQexecParams \
	-Wl,--wrap=PQresultStatus \
	-Wl,--wrap=PQntuples \
	-Wl,--wrap=PQnfields \
	-Wl,--wrap=PQgetisnull \
	-Wl,--wrap=PQgetvalue \
	-Wl,--wrap=PQresultErrorMessage \
	-Wl,--wrap=PQerrorMessage \
	-Wl,--wrap=PQclear \
	-Wl,--wrap=PQfinish

BASE_CFLAGS := -std=c11 -O2 -g \
	-Wall -Wextra -Wpedantic -Werror \
	-Wformat=2 -Wshadow -Wstrict-prototypes -Wmissing-prototypes
SANITIZER_FLAGS := -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
THREAD_SANITIZER_FLAGS := -O1 -fno-omit-frame-pointer -fsanitize=thread

NORMAL_DIR := build/normal
SANITIZER_DIR := build/sanitize

PROTOCOL_SOURCES := src/ftap_codec.c src/ftap_schema.c
DATABASE_VALIDATION_SOURCE := src/authd_database_validation.c
DATABASE_SOURCE := src/authd_database.c $(DATABASE_VALIDATION_SOURCE)
PASSWORD_SOURCE := src/authd_password.c
WORKER_POOL_SOURCE := src/authd_worker_pool.c
IDENTITY_SOURCE := src/authd_identity.c
THROTTLE_SOURCE := src/authd_throttle.c
AUTHD_COMMON_SOURCES := \
	$(PROTOCOL_SOURCES) \
	src/authd_config.c \
	src/authd_peer.c \
	src/authd_server.c
AUTHD_PRODUCTION_SOURCES := \
	$(AUTHD_COMMON_SOURCES) \
	$(IDENTITY_SOURCE) \
	$(THROTTLE_SOURCE) \
	$(DATABASE_SOURCE) \
	$(PASSWORD_SOURCE) \
	$(WORKER_POOL_SOURCE)
AUTHD_TEST_SOURCES := $(AUTHD_COMMON_SOURCES) tests/authd_database_stub.c

NORMAL_TESTS := \
	$(NORMAL_DIR)/ftap_protocol_compile_test \
	$(NORMAL_DIR)/ftap_codec_test \
	$(NORMAL_DIR)/ftap_schema_test \
	$(NORMAL_DIR)/authd_config_test \
	$(NORMAL_DIR)/authd_identity_test \
	$(NORMAL_DIR)/authd_throttle_test \
	$(NORMAL_DIR)/authd_password_test \
	$(NORMAL_DIR)/authd_worker_pool_test \
	$(NORMAL_DIR)/authd_worker_pool_password_integration_test \
	$(NORMAL_DIR)/authd_peer_test \
	$(NORMAL_DIR)/authd_database_validation_test \
	$(NORMAL_DIR)/authd_database_mock_test \
	$(NORMAL_DIR)/authd_database_connection_test \
	$(NORMAL_DIR)/authd_integration_test

.PHONY: all authd test database-login-integration-test database-throttle-integration-test sanitize-test thread-sanitize-test analyze check-libpq check-libsodium clean

all: authd test

authd: check-libpq check-libsodium $(NORMAL_DIR)/fortytwo-authd

test: check-libpq check-libsodium $(NORMAL_DIR)/fortytwo-authd \
	$(NORMAL_DIR)/fortytwo-authd-test $(NORMAL_TESTS)
	$(NORMAL_DIR)/ftap_protocol_compile_test
	$(NORMAL_DIR)/ftap_codec_test
	$(NORMAL_DIR)/ftap_schema_test
	$(NORMAL_DIR)/authd_config_test
	$(NORMAL_DIR)/authd_identity_test
	$(NORMAL_DIR)/authd_throttle_test
	$(NORMAL_DIR)/authd_password_test
	$(NORMAL_DIR)/authd_worker_pool_test
	$(NORMAL_DIR)/authd_worker_pool_password_integration_test
	$(NORMAL_DIR)/authd_peer_test
	$(NORMAL_DIR)/authd_database_validation_test
	$(NORMAL_DIR)/authd_database_mock_test
	$(NORMAL_DIR)/authd_database_connection_test
	$(NORMAL_DIR)/authd_integration_test $(NORMAL_DIR)/fortytwo-authd-test

check-libpq:
	@test -n "$(LIBPQ_CFLAGS)" -o -n "$(LIBPQ_LIBS)" || { \
		echo "libpq development files not found (install libpq-dev)" >&2; \
		exit 1; \
	}

check-libsodium:
	@test -n "$(SODIUM_CFLAGS)" -o -n "$(SODIUM_LIBS)" || { \
		echo "libsodium development files not found (install libsodium-dev)" >&2; \
		exit 1; \
	}

$(NORMAL_DIR):
	mkdir -p $@

$(NORMAL_DIR)/ftap_protocol_compile_test: tests/ftap_protocol_compile_test.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $< -o $@

$(NORMAL_DIR)/ftap_codec_test: tests/ftap_codec_test.c src/ftap_codec.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/ftap_codec.c $< -o $@

$(NORMAL_DIR)/ftap_schema_test: tests/ftap_schema_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -o $@

$(NORMAL_DIR)/fortytwo-authd: src/fortytwo_authd.c $(AUTHD_PRODUCTION_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_FLAGS) \
		$(AUTHD_PRODUCTION_SOURCES) src/fortytwo_authd.c \
		$(LIBPQ_LIBS) $(SODIUM_LIBS) -o $@

$(NORMAL_DIR)/fortytwo-authd-test: src/fortytwo_authd.c $(AUTHD_TEST_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(AUTHD_TEST_SOURCES) \
		src/fortytwo_authd.c -o $@

$(NORMAL_DIR)/authd_config_test: tests/authd_config_test.c src/authd_config.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $< -o $@

$(NORMAL_DIR)/authd_identity_test: tests/authd_identity_test.c $(IDENTITY_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(IDENTITY_SOURCE) $< -o $@

$(NORMAL_DIR)/authd_throttle_test: tests/authd_throttle_test.c $(THROTTLE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THROTTLE_SOURCE) $< -o $@

$(NORMAL_DIR)/authd_password_test: tests/authd_password_test.c $(PASSWORD_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PASSWORD_SOURCE) $< $(SODIUM_LIBS) -o $@

$(NORMAL_DIR)/authd_worker_pool_test: tests/authd_worker_pool_test.c tests/authd_password_worker_stub.c $(WORKER_POOL_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_FLAGS) \
		$(WORKER_POOL_SOURCE) tests/authd_password_worker_stub.c $< -o $@

$(NORMAL_DIR)/authd_worker_pool_password_integration_test: tests/authd_worker_pool_password_integration_test.c $(PASSWORD_SOURCE) $(WORKER_POOL_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_FLAGS) \
		$(PASSWORD_SOURCE) $(WORKER_POOL_SOURCE) $< $(SODIUM_LIBS) -o $@

$(NORMAL_DIR)/authd_peer_test: tests/authd_peer_test.c src/authd_config.c src/authd_peer.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c src/authd_peer.c $< -o $@

$(NORMAL_DIR)/authd_database_validation_test: tests/authd_database_validation_test.c $(DATABASE_VALIDATION_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(DATABASE_VALIDATION_SOURCE) $< -o $@

$(NORMAL_DIR)/authd_database_mock_test: tests/authd_database_mock_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		$< $(LIBPQ_WRAP_FLAGS) -o $@

$(NORMAL_DIR)/authd_database_connection_test: tests/authd_database_connection_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		$< $(LIBPQ_LIBS) -o $@

$(NORMAL_DIR)/authd_database_login_integration_test: tests/authd_database_login_integration_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		$< $(LIBPQ_LIBS) -o $@

database-login-integration-test: check-libpq $(NORMAL_DIR)/authd_database_login_integration_test
	tests/run_authd_database_login_integration.sh \
		$(NORMAL_DIR)/authd_database_login_integration_test

$(NORMAL_DIR)/authd_database_throttle_integration_test: tests/authd_database_throttle_integration_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		$< $(LIBPQ_LIBS) -o $@

database-throttle-integration-test: check-libpq $(NORMAL_DIR)/authd_database_throttle_integration_test
	tests/run_authd_database_throttle_integration.sh \
		$(NORMAL_DIR)/authd_database_throttle_integration_test

$(NORMAL_DIR)/authd_integration_test: tests/authd_integration_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -o $@

sanitize-test: check-libpq check-libsodium
	mkdir -p $(SANITIZER_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		tests/ftap_protocol_compile_test.c \
		-o $(SANITIZER_DIR)/ftap_protocol_compile_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/ftap_codec.c tests/ftap_codec_test.c \
		-o $(SANITIZER_DIR)/ftap_codec_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(PROTOCOL_SOURCES) tests/ftap_schema_test.c \
		-o $(SANITIZER_DIR)/ftap_schema_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(AUTHD_PRODUCTION_SOURCES) src/fortytwo_authd.c \
		$(LIBPQ_LIBS) $(SODIUM_LIBS) -o $(SANITIZER_DIR)/fortytwo-authd
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(AUTHD_TEST_SOURCES) src/fortytwo_authd.c \
		-o $(SANITIZER_DIR)/fortytwo-authd-test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c tests/authd_config_test.c \
		-o $(SANITIZER_DIR)/authd_config_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(IDENTITY_SOURCE) tests/authd_identity_test.c \
		-o $(SANITIZER_DIR)/authd_identity_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(THROTTLE_SOURCE) tests/authd_throttle_test.c \
		-o $(SANITIZER_DIR)/authd_throttle_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(PASSWORD_SOURCE) tests/authd_password_test.c $(SODIUM_LIBS) \
		-o $(SANITIZER_DIR)/authd_password_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(WORKER_POOL_SOURCE) tests/authd_password_worker_stub.c \
		tests/authd_worker_pool_test.c \
		-o $(SANITIZER_DIR)/authd_worker_pool_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(PASSWORD_SOURCE) $(WORKER_POOL_SOURCE) \
		tests/authd_worker_pool_password_integration_test.c $(SODIUM_LIBS) \
		-o $(SANITIZER_DIR)/authd_worker_pool_password_integration_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c src/authd_peer.c tests/authd_peer_test.c \
		-o $(SANITIZER_DIR)/authd_peer_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(DATABASE_VALIDATION_SOURCE) tests/authd_database_validation_test.c \
		-o $(SANITIZER_DIR)/authd_database_validation_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		tests/authd_database_mock_test.c $(LIBPQ_WRAP_FLAGS) \
		-o $(SANITIZER_DIR)/authd_database_mock_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		tests/authd_database_connection_test.c $(LIBPQ_LIBS) \
		-o $(SANITIZER_DIR)/authd_database_connection_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(PROTOCOL_SOURCES) tests/authd_integration_test.c \
		-o $(SANITIZER_DIR)/authd_integration_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/ftap_protocol_compile_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/ftap_codec_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/ftap_schema_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_config_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_identity_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_throttle_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_password_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_worker_pool_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_worker_pool_password_integration_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_peer_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_validation_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_mock_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_connection_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_integration_test \
		$(SANITIZER_DIR)/fortytwo-authd-test

thread-sanitize-test:
	mkdir -p $(SANITIZER_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(WORKER_POOL_SOURCE) tests/authd_password_worker_stub.c \
		tests/authd_worker_pool_test.c \
		-o $(SANITIZER_DIR)/authd_worker_pool_thread_test
	TSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_worker_pool_thread_test

analyze: check-libpq check-libsodium
	@set -e; \
	for source in $(AUTHD_PRODUCTION_SOURCES) src/fortytwo_authd.c; do \
		clang --analyze $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_FLAGS) "$$source" \
			-o /dev/null; \
	done

clean:
	rm -rf build
