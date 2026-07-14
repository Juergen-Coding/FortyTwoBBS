CC ?= cc

CPPFLAGS := -D_GNU_SOURCE -Iinclude
BASE_CFLAGS := -std=c11 -O2 -g \
	-Wall -Wextra -Wpedantic -Werror \
	-Wformat=2 -Wshadow -Wstrict-prototypes -Wmissing-prototypes
SANITIZER_FLAGS := -O1 -fno-omit-frame-pointer -fsanitize=address,undefined

NORMAL_DIR := build/normal
SANITIZER_DIR := build/sanitize

PROTOCOL_SOURCES := src/ftap_codec.c src/ftap_schema.c
AUTHD_SOURCES := \
	$(PROTOCOL_SOURCES) \
	src/authd_config.c \
	src/authd_peer.c \
	src/authd_server.c

NORMAL_TESTS := \
	$(NORMAL_DIR)/ftap_protocol_compile_test \
	$(NORMAL_DIR)/ftap_codec_test \
	$(NORMAL_DIR)/ftap_schema_test \
	$(NORMAL_DIR)/authd_config_test \
	$(NORMAL_DIR)/authd_peer_test \
	$(NORMAL_DIR)/authd_integration_test

.PHONY: all authd test sanitize-test clean

all: authd test

authd: $(NORMAL_DIR)/fortytwo-authd

test: $(NORMAL_DIR)/fortytwo-authd $(NORMAL_TESTS)
	$(NORMAL_DIR)/ftap_protocol_compile_test
	$(NORMAL_DIR)/ftap_codec_test
	$(NORMAL_DIR)/ftap_schema_test
	$(NORMAL_DIR)/authd_config_test
	$(NORMAL_DIR)/authd_peer_test
	$(NORMAL_DIR)/authd_integration_test $(NORMAL_DIR)/fortytwo-authd

$(NORMAL_DIR):
	mkdir -p $@

$(NORMAL_DIR)/ftap_protocol_compile_test: tests/ftap_protocol_compile_test.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $< -o $@

$(NORMAL_DIR)/ftap_codec_test: tests/ftap_codec_test.c src/ftap_codec.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/ftap_codec.c $< -o $@

$(NORMAL_DIR)/ftap_schema_test: tests/ftap_schema_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -o $@

$(NORMAL_DIR)/fortytwo-authd: src/fortytwo_authd.c $(AUTHD_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(AUTHD_SOURCES) src/fortytwo_authd.c -o $@

$(NORMAL_DIR)/authd_config_test: tests/authd_config_test.c src/authd_config.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c $< -o $@

$(NORMAL_DIR)/authd_peer_test: tests/authd_peer_test.c src/authd_config.c src/authd_peer.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/authd_config.c src/authd_peer.c $< -o $@

$(NORMAL_DIR)/authd_integration_test: tests/authd_integration_test.c $(PROTOCOL_SOURCES) | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(PROTOCOL_SOURCES) $< -o $@

sanitize-test:
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
		$(AUTHD_SOURCES) src/fortytwo_authd.c \
		-o $(SANITIZER_DIR)/fortytwo-authd
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c tests/authd_config_test.c \
		-o $(SANITIZER_DIR)/authd_config_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/authd_config.c src/authd_peer.c tests/authd_peer_test.c \
		-o $(SANITIZER_DIR)/authd_peer_test
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
		$(SANITIZER_DIR)/authd_peer_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/authd_integration_test $(SANITIZER_DIR)/fortytwo-authd

clean:
	rm -rf build
