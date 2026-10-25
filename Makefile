CC ?= gcc
# POSIX feature flags expose the APIs used by the server and terminal client.
CPPFLAGS += -Isrc -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
# Only the server needs OpenSSL, pthreads, and the real-time library for semaphores.
LDLIBS += -lcrypto -pthread -lrt

BUILD_DIR := build
STORE := src/store.c
HEADER := src/bank.h

# Default target compiles two independent programs: a server and a terminal client.
.PHONY: all clean

all: $(BUILD_DIR)/bank_server $(BUILD_DIR)/bank_client

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/bank_server: src/server.c $(STORE) $(HEADER) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/server.c $(STORE) -o $@ $(LDLIBS)

# The client is a separate executable and needs no database or crypto linkage.
$(BUILD_DIR)/bank_client: src/client.c $(HEADER) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/client.c -o $@

# Remove generated binaries; source, documentation, and database data are untouched.
clean:
	rm -rf $(BUILD_DIR)
