CC ?= cc

CPPFLAGS := -Iinclude
BASE_CFLAGS := -std=c11 -O2 -g \
	-Wall -Wextra -Wpedantic -Werror \
	-Wformat=2 -Wshadow -Wstrict-prototypes -Wmissing-prototypes
SANITIZER_FLAGS := -O1 -fno-omit-frame-pointer -fsanitize=address,undefined

NORMAL_DIR := build/normal
SANITIZER_DIR := build/sanitize

.PHONY: all test sanitize-test clean

all: test

test: \
	$(NORMAL_DIR)/ftap_protocol_compile_test \
	$(NORMAL_DIR)/ftap_codec_test \
	$(NORMAL_DIR)/ftap_schema_test
	$(NORMAL_DIR)/ftap_protocol_compile_test
	$(NORMAL_DIR)/ftap_codec_test
	$(NORMAL_DIR)/ftap_schema_test

$(NORMAL_DIR):
	mkdir -p $@

$(NORMAL_DIR)/ftap_protocol_compile_test: tests/ftap_protocol_compile_test.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $< -o $@

$(NORMAL_DIR)/ftap_codec_test: tests/ftap_codec_test.c src/ftap_codec.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/ftap_codec.c $< -o $@

$(NORMAL_DIR)/ftap_schema_test: tests/ftap_schema_test.c src/ftap_codec.c src/ftap_schema.c | $(NORMAL_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) src/ftap_codec.c src/ftap_schema.c $< -o $@

sanitize-test:
	mkdir -p $(SANITIZER_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		tests/ftap_protocol_compile_test.c \
		-o $(SANITIZER_DIR)/ftap_protocol_compile_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/ftap_codec.c tests/ftap_codec_test.c \
		-o $(SANITIZER_DIR)/ftap_codec_test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(SANITIZER_FLAGS) \
		src/ftap_codec.c src/ftap_schema.c tests/ftap_schema_test.c \
		-o $(SANITIZER_DIR)/ftap_schema_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/ftap_protocol_compile_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/ftap_codec_test
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
		$(SANITIZER_DIR)/ftap_schema_test

clean:
	rm -rf build
