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
PUBLIC_HEADERS := $(wildcard include/*.h)

PROTOCOL_SOURCES := src/ftap_codec.c src/ftap_schema.c
FTAP_CLIENT_SOURCES := $(PROTOCOL_SOURCES) src/ftap_client.c
MBSE_SESSION_SOURCE := ../mbsebbs/fortytwo_session.c
DATABASE_VALIDATION_SOURCE := src/authd_database_validation.c
DATABASE_SOURCE := src/authd_database.c $(DATABASE_VALIDATION_SOURCE)
PASSWORD_SOURCE := src/authd_password.c
WORKER_POOL_SOURCE := src/authd_worker_pool.c
IDENTITY_SOURCE := src/authd_identity.c
THROTTLE_SOURCE := src/authd_throttle.c
REGISTRATION_LIMIT_SOURCE := src/authd_registration_limit.c
LEGACY_USERDB_READ_SOURCE := src/legacy_userdb.c
LEGACY_USERDB_PROVISION_SOURCE := src/legacy_userdb_provision.c
LEGACY_REGISTRATION_MARKER_SOURCE := src/legacy_registration_marker.c
LEGACY_USERDB_SOURCES := \
	$(LEGACY_USERDB_READ_SOURCE) \
	$(LEGACY_USERDB_PROVISION_SOURCE)
REGISTRATION_COORDINATOR_SOURCE := src/registration_coordinator.c
TERMINAL_GATE_SOURCE := src/terminal_gate.c
LOGIN_SOURCES := \
	$(FTAP_CLIENT_SOURCES) \
	$(LEGACY_USERDB_SOURCES) \
	$(REGISTRATION_COORDINATOR_SOURCE) \
	$(TERMINAL_GATE_SOURCE) \
	src/fortytwo_login.c
AUTHD_COMMON_SOURCES := \
	$(PROTOCOL_SOURCES) \
	src/authd_config.c \
	src/authd_peer.c \
	src/authd_server.c
AUTHD_PRODUCTION_SOURCES := \
	$(AUTHD_COMMON_SOURCES) \
	$(IDENTITY_SOURCE) \
	$(THROTTLE_SOURCE) \
	$(REGISTRATION_LIMIT_SOURCE) \
	$(DATABASE_SOURCE) \
	$(PASSWORD_SOURCE) \
	$(WORKER_POOL_SOURCE)
AUTHD_TEST_SOURCES := \
	$(AUTHD_COMMON_SOURCES) \
	$(IDENTITY_SOURCE) \
	$(THROTTLE_SOURCE) \
	$(REGISTRATION_LIMIT_SOURCE) \
	$(WORKER_POOL_SOURCE) \
	tests/authd_password_worker_stub.c \
	tests/authd_database_stub.c

NORMAL_TESTS := \
	$(NORMAL_DIR)/ftap_protocol_compile_test \
	$(NORMAL_DIR)/ftap_codec_test \
	$(NORMAL_DIR)/ftap_schema_test \
	$(NORMAL_DIR)/ftap_client_registration_test \
	$(NORMAL_DIR)/legacy_userdb_test \
	$(NORMAL_DIR)/legacy_registration_marker_test \
	$(NORMAL_DIR)/legacy_userdb_provision_test \
	$(NORMAL_DIR)/registration_coordinator_test \
	$(NORMAL_DIR)/registration_coordinator_integration_test \
	$(NORMAL_DIR)/terminal_gate_test \
	$(NORMAL_DIR)/authd_config_test \
	$(NORMAL_DIR)/authd_identity_test \
	$(NORMAL_DIR)/authd_throttle_test \
	$(NORMAL_DIR)/authd_registration_limit_test \
	$(NORMAL_DIR)/authd_password_test \
	$(NORMAL_DIR)/authd_worker_pool_test \
	$(NORMAL_DIR)/authd_worker_pool_password_integration_test \
	$(NORMAL_DIR)/authd_peer_test \
	$(NORMAL_DIR)/authd_database_validation_test \
	$(NORMAL_DIR)/authd_database_mock_test \
	$(NORMAL_DIR)/authd_database_registration_mock_test \
	$(NORMAL_DIR)/authd_database_connection_test \
	$(NORMAL_DIR)/authd_integration_test \
	$(NORMAL_DIR)/authd_registration_server_integration_test

.PHONY: all authd login test users-data-access-check database-login-integration-test database-throttle-integration-test database-session-integration-test database-registration-integration-test sanitize-test thread-sanitize-test analyze check-libpq check-libsodium clean

all: authd login test

authd: check-libpq check-libsodium $(NORMAL_DIR)/fortytwo-authd

login: $(NORMAL_DIR)/fortytwo-login

test: check-libpq check-libsodium users-data-access-check $(NORMAL_DIR)/fortytwo-authd \
	$(NORMAL_DIR)/fortytwo-authd-test $(NORMAL_DIR)/fortytwo-login \
	$(NORMAL_DIR)/fortytwo-login-dialog-test \
	$(NORMAL_DIR)/fortytwo-session-child-test $(NORMAL_TESTS)
	$(NORMAL_DIR)/ftap_protocol_compile_test
	$(NORMAL_DIR)/ftap_codec_test
	$(NORMAL_DIR)/ftap_schema_test
	$(NORMAL_DIR)/ftap_client_registration_test
	$(NORMAL_DIR)/legacy_userdb_test
	$(NORMAL_DIR)/legacy_registration_marker_test
	$(NORMAL_DIR)/legacy_userdb_provision_test
	$(NORMAL_DIR)/registration_coordinator_test
	$(NORMAL_DIR)/registration_coordinator_integration_test
	$(NORMAL_DIR)/terminal_gate_test
	python3 tests/fortytwo_login_dialog_test.py \
		$(abspath $(NORMAL_DIR)/fortytwo-login-dialog-test)
	$(NORMAL_DIR)/authd_config_test
	$(NORMAL_DIR)/authd_identity_test
	$(NORMAL_DIR)/authd_throttle_test
	$(NORMAL_DIR)/authd_registration_limit_test
	$(NORMAL_DIR)/authd_password_test
	$(NORMAL_DIR)/authd_worker_pool_test
	$(NORMAL_DIR)/authd_worker_pool_password_integration_test
	$(NORMAL_DIR)/authd_peer_test
	python3 tests/migration_0009_test.py
	$(NORMAL_DIR)/authd_database_validation_test
	$(NORMAL_DIR)/authd_database_mock_test
	$(NORMAL_DIR)/authd_database_registration_mock_test
	$(NORMAL_DIR)/authd_database_connection_test
	$(NORMAL_DIR)/authd_integration_test $(NORMAL_DIR)/fortytwo-authd-test \
		$(abspath $(NORMAL_DIR)/fortytwo-login) \
		$(abspath $(NORMAL_DIR)/fortytwo-session-child-test)
	$(NORMAL_DIR)/authd_registration_server_integration_test \
		$(abspath $(NORMAL_DIR)/fortytwo-authd-test)

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

users-data-access-check:
	python3 tests/check_users_data_access.py

$(NORMAL_DIR):
	mkdir -p $@

$(NORMAL_TESTS) \
$(NORMAL_DIR)/fortytwo-authd \
$(NORMAL_DIR)/fortytwo-authd-test \
$(NORMAL_DIR)/fortytwo-login \
$(NORMAL_DIR)/fortytwo-login-dialog-test \
$(NORMAL_DIR)/fortytwo-session-child-test \
$(NORMAL_DIR)/authd_database_login_integration_test \
$(NORMAL_DIR)/authd_database_throttle_integration_test \
$(NORMAL_DIR)/authd_database_session_integration_test \
$(NORMAL_DIR)/authd_database_registration_integration_test: $(PUBLIC_HEADERS)

$(NORMAL_DIR)/ftap_protocol_compile_test: tests/ftap_protocol_compile_test.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $< -o $@

$(NORMAL_DIR)/ftap_codec_test: tests/ftap_codec_test.c src/ftap_codec.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/ftap_codec.c $< -o $@

$(NORMAL_DIR)/ftap_schema_test: tests/ftap_schema_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -o $@

$(NORMAL_DIR)/ftap_client_registration_test: tests/ftap_client_registration_test.c $(FTAP_CLIENT_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(FTAP_CLIENT_SOURCES) $< -o $@

$(NORMAL_DIR)/legacy_userdb_test: tests/legacy_userdb_test.c $(LEGACY_USERDB_READ_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(LEGACY_USERDB_READ_SOURCE) $< -o $@

$(NORMAL_DIR)/legacy_registration_marker_test: tests/legacy_registration_marker_test.c $(LEGACY_REGISTRATION_MARKER_SOURCE) $(LEGACY_USERDB_READ_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) -DLEGACY_REGISTRATION_MARKER_TESTING $(BASE_CFLAGS) \
		$(LEGACY_USERDB_READ_SOURCE) $(LEGACY_REGISTRATION_MARKER_SOURCE) $< -o $@

$(NORMAL_DIR)/legacy_userdb_provision_test: tests/legacy_userdb_provision_test.c $(LEGACY_USERDB_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) -DLEGACY_USERDB_TESTING $(BASE_CFLAGS) \
		$(LEGACY_USERDB_SOURCES) $< -o $@

$(NORMAL_DIR)/registration_coordinator_test: tests/registration_coordinator_test.c $(REGISTRATION_COORDINATOR_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(REGISTRATION_COORDINATOR_SOURCE) $< -o $@

$(NORMAL_DIR)/registration_coordinator_integration_test: tests/registration_coordinator_integration_test.c $(REGISTRATION_COORDINATOR_SOURCE) $(FTAP_CLIENT_SOURCES) $(LEGACY_USERDB_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(FTAP_CLIENT_SOURCES) \
		$(LEGACY_USERDB_SOURCES) $(REGISTRATION_COORDINATOR_SOURCE) $< -o $@

$(NORMAL_DIR)/terminal_gate_test: tests/terminal_gate_test.c $(TERMINAL_GATE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) -DTERMINAL_GATE_TESTING $(BASE_CFLAGS) \
		$(TERMINAL_GATE_SOURCE) $< -lutil -o $@

$(NORMAL_DIR)/fortytwo-authd: src/fortytwo_authd.c $(AUTHD_PRODUCTION_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_FLAGS) \
		$(AUTHD_PRODUCTION_SOURCES) src/fortytwo_authd.c \
		$(LIBPQ_LIBS) $(SODIUM_LIBS) -o $@

$(NORMAL_DIR)/fortytwo-authd-test: src/fortytwo_authd.c $(AUTHD_TEST_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) -DAUTHD_TESTING $(BASE_CFLAGS) $(THREAD_FLAGS) \
		$(AUTHD_TEST_SOURCES) \
		src/fortytwo_authd.c -o $@

$(NORMAL_DIR)/fortytwo-login: $(LOGIN_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(LOGIN_SOURCES) -o $@

$(NORMAL_DIR)/fortytwo-login-dialog-test: $(LOGIN_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) -DTERMINAL_GATE_TESTING $(BASE_CFLAGS) \
		$(LOGIN_SOURCES) -o $@

$(NORMAL_DIR)/fortytwo-session-child-test: tests/fortytwo_session_child_test.c $(FTAP_CLIENT_SOURCES) $(MBSE_SESSION_SOURCE) ../mbsebbs/fortytwo_session.h | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(FTAP_CLIENT_SOURCES) $(MBSE_SESSION_SOURCE) $< -o $@

$(NORMAL_DIR)/authd_config_test: tests/authd_config_test.c src/authd_config.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $< -o $@

$(NORMAL_DIR)/authd_identity_test: tests/authd_identity_test.c $(IDENTITY_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(IDENTITY_SOURCE) $< -o $@

$(NORMAL_DIR)/authd_throttle_test: tests/authd_throttle_test.c $(THROTTLE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THROTTLE_SOURCE) $< -o $@

$(NORMAL_DIR)/authd_registration_limit_test: tests/authd_registration_limit_test.c $(REGISTRATION_LIMIT_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(REGISTRATION_LIMIT_SOURCE) $< -o $@

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

$(NORMAL_DIR)/authd_database_registration_mock_test: tests/authd_database_registration_mock_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
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

$(NORMAL_DIR)/authd_database_session_integration_test: tests/authd_database_session_integration_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		$< $(LIBPQ_LIBS) -o $@

database-session-integration-test: check-libpq $(NORMAL_DIR)/authd_database_session_integration_test
	tests/run_authd_database_session_integration.sh \
		$(NORMAL_DIR)/authd_database_session_integration_test

$(NORMAL_DIR)/authd_database_registration_integration_test: tests/authd_database_registration_integration_test.c src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		$< $(LIBPQ_LIBS) -o $@

database-registration-integration-test: check-libpq $(NORMAL_DIR)/authd_database_registration_integration_test
	tests/run_authd_database_registration_integration.sh \
		$(NORMAL_DIR)/authd_database_registration_integration_test

$(NORMAL_DIR)/authd_integration_test: tests/authd_integration_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -lutil -o $@

$(NORMAL_DIR)/authd_registration_server_integration_test: tests/authd_registration_server_integration_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -o $@

sanitize-test: check-libpq check-libsodium users-data-access-check
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
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(FTAP_CLIENT_SOURCES) tests/ftap_client_registration_test.c \
		-o $(SANITIZER_DIR)/ftap_client_registration_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(LEGACY_USERDB_READ_SOURCE) tests/legacy_userdb_test.c \
		-o $(SANITIZER_DIR)/legacy_userdb_test
	$(CC) $(CPPFLAGS) -DLEGACY_REGISTRATION_MARKER_TESTING \
		$(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(LEGACY_USERDB_READ_SOURCE) $(LEGACY_REGISTRATION_MARKER_SOURCE) \
		tests/legacy_registration_marker_test.c \
		-o $(SANITIZER_DIR)/legacy_registration_marker_test
	$(CC) $(CPPFLAGS) -DLEGACY_USERDB_TESTING $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(LEGACY_USERDB_SOURCES) tests/legacy_userdb_provision_test.c \
		-o $(SANITIZER_DIR)/legacy_userdb_provision_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(REGISTRATION_COORDINATOR_SOURCE) tests/registration_coordinator_test.c \
		-o $(SANITIZER_DIR)/registration_coordinator_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(FTAP_CLIENT_SOURCES) $(LEGACY_USERDB_SOURCES) \
		$(REGISTRATION_COORDINATOR_SOURCE) \
		tests/registration_coordinator_integration_test.c \
		-o $(SANITIZER_DIR)/registration_coordinator_integration_test
	$(CC) $(CPPFLAGS) -DTERMINAL_GATE_TESTING $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(TERMINAL_GATE_SOURCE) tests/terminal_gate_test.c -lutil \
		-o $(SANITIZER_DIR)/terminal_gate_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(AUTHD_PRODUCTION_SOURCES) src/fortytwo_authd.c \
		$(LIBPQ_LIBS) $(SODIUM_LIBS) -o $(SANITIZER_DIR)/fortytwo-authd
	$(CC) $(CPPFLAGS) -DAUTHD_TESTING $(BASE_CFLAGS) $(SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(AUTHD_TEST_SOURCES) src/fortytwo_authd.c \
		-o $(SANITIZER_DIR)/fortytwo-authd-test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(LOGIN_SOURCES) -o $(SANITIZER_DIR)/fortytwo-login
	$(CC) $(CPPFLAGS) -DTERMINAL_GATE_TESTING $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(LOGIN_SOURCES) -o $(SANITIZER_DIR)/fortytwo-login-dialog-test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(FTAP_CLIENT_SOURCES) $(MBSE_SESSION_SOURCE) \
		tests/fortytwo_session_child_test.c \
		-o $(SANITIZER_DIR)/fortytwo-session-child-test
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
		$(REGISTRATION_LIMIT_SOURCE) tests/authd_registration_limit_test.c \
		-o $(SANITIZER_DIR)/authd_registration_limit_test
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
		tests/authd_database_registration_mock_test.c $(LIBPQ_WRAP_FLAGS) \
		-o $(SANITIZER_DIR)/authd_database_registration_mock_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c $(IDENTITY_SOURCE) $(THROTTLE_SOURCE) $(DATABASE_SOURCE) \
		tests/authd_database_connection_test.c $(LIBPQ_LIBS) \
		-o $(SANITIZER_DIR)/authd_database_connection_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(PROTOCOL_SOURCES) tests/authd_integration_test.c -lutil \
		-o $(SANITIZER_DIR)/authd_integration_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		$(PROTOCOL_SOURCES) tests/authd_registration_server_integration_test.c \
		-o $(SANITIZER_DIR)/authd_registration_server_integration_test
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
		$(SANITIZER_DIR)/ftap_client_registration_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/legacy_userdb_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/legacy_registration_marker_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/legacy_userdb_provision_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/registration_coordinator_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/registration_coordinator_integration_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/terminal_gate_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		python3 tests/fortytwo_login_dialog_test.py \
		$(abspath $(SANITIZER_DIR)/fortytwo-login-dialog-test)
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
		$(SANITIZER_DIR)/authd_registration_limit_test
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
	python3 tests/migration_0009_test.py
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_validation_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_mock_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_registration_mock_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_database_connection_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_integration_test \
		$(SANITIZER_DIR)/fortytwo-authd-test \
		$(abspath $(SANITIZER_DIR)/fortytwo-login) \
		$(abspath $(SANITIZER_DIR)/fortytwo-session-child-test)
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_registration_server_integration_test \
		$(abspath $(SANITIZER_DIR)/fortytwo-authd-test)

thread-sanitize-test:
	mkdir -p $(SANITIZER_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(WORKER_POOL_SOURCE) tests/authd_password_worker_stub.c \
		tests/authd_worker_pool_test.c \
		-o $(SANITIZER_DIR)/authd_worker_pool_thread_test
	$(CC) $(CPPFLAGS) -DAUTHD_TESTING $(BASE_CFLAGS) \
		$(THREAD_SANITIZER_FLAGS) $(THREAD_FLAGS) \
		$(AUTHD_TEST_SOURCES) src/fortytwo_authd.c \
		-o $(SANITIZER_DIR)/fortytwo-authd-thread-test
	$(CC) $(CPPFLAGS) -DTEST_TIMEOUT_MS=10000 $(BASE_CFLAGS) \
		$(PROTOCOL_SOURCES) tests/authd_integration_test.c -lutil \
		-o $(SANITIZER_DIR)/authd_integration_thread_driver
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_SANITIZER_FLAGS) \
		$(LOGIN_SOURCES) -o $(SANITIZER_DIR)/fortytwo-login-thread-test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_SANITIZER_FLAGS) \
		$(FTAP_CLIENT_SOURCES) $(MBSE_SESSION_SOURCE) \
		tests/fortytwo_session_child_test.c \
		-o $(SANITIZER_DIR)/fortytwo-session-child-thread-test
	TSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_worker_pool_thread_test
	TSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_integration_thread_driver \
		$(SANITIZER_DIR)/fortytwo-authd-thread-test \
		$(abspath $(SANITIZER_DIR)/fortytwo-login-thread-test) \
		$(abspath $(SANITIZER_DIR)/fortytwo-session-child-thread-test)

analyze: check-libpq check-libsodium
	@set -e; \
	for source in $(AUTHD_PRODUCTION_SOURCES) src/fortytwo_authd.c \
		src/ftap_client.c src/fortytwo_login.c $(LEGACY_USERDB_SOURCES) \
		$(LEGACY_REGISTRATION_MARKER_SOURCE) \
		$(REGISTRATION_COORDINATOR_SOURCE) $(TERMINAL_GATE_SOURCE) $(MBSE_SESSION_SOURCE); do \
		clang --analyze $(CPPFLAGS) $(BASE_CFLAGS) $(THREAD_FLAGS) "$$source" \
			-o /dev/null; \
	done

clean:
	rm -rf build
