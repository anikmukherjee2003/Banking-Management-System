#define _POSIX_C_SOURCE 200809L

#include "bank.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#define PASSWORD_ROUNDS 120000
#define SESSION_LIFETIME (12 * 60 * 60)
#define MAX_AMOUNT_PAISE 100000000000LL

/*
 * This module is the authoritative banking layer. The client sends commands,
 * but every role and business rule is checked here. Each operation works on a
 * freshly loaded snapshot while holding the semaphore and file lock; changed
 * snapshots are committed through a temporary file and atomic rename.
 *
 * Request path: client text -> bank_execute() -> run_locked() -> one callback
 * (login, authenticated command, or disconnect cleanup) -> response text.
 * The callback edits only its private BankState snapshot; run_locked() decides
 * whether that snapshot should replace the on-disk database.
 */
/*
 * Temporary context passed to an operation callback. Keeping the parsed fields,
 * session, and response together avoids giving every command a long parameter list.
 */
typedef struct {
    char **fields;
    size_t count;
    BankSession *session;
    BankResponse *response;
} RequestContext;

/* Callbacks return nonzero when run_locked() must save the updated snapshot. */
typedef int (*StateOperation)(BankState *, void *);

static void state_reset(BankState *state) {
    /*
     * Clear all records and reset each generated ID. This is used before loading
     * the first file and when starting a brand-new database, so no old array
     * contents can accidentally be treated as valid records.
     */
    memset(state, 0, sizeof(*state));
    state->next_account = 1;
    state->next_transaction = 1;
    state->next_loan = 1;
    state->next_feedback = 1;
}

static int response_line(BankResponse *response, const char *format, ...) {
    /*
     * Append formatted text at response->length. vsnprintf() always reserves a
     * trailing NUL; returning -1 means the caller must stop adding response data.
     */
    if (response->length >= sizeof(response->data)) return -1;
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(response->data + response->length,
                            sizeof(response->data) - response->length,
                            format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= sizeof(response->data) - response->length) return -1;
    response->length += (size_t)written;
    return 0;
}

static void response_end(BankResponse *response) {
    /* The client uses this sentinel to know that all rows for one command arrived. */
    response_line(response, "END\n");
}

static void response_error(BankResponse *response, const char *message) {
    /*
     * Discard any success/data lines already assembled, then send one ERROR line.
     * This makes error responses unambiguous even if a handler failed midway.
     */
    response->length = 0;
    response->data[0] = '\0';
    response_line(response, "ERROR|%s\n", message);
    response_end(response);
}

static void response_ok(BankResponse *response, const char *message) {
    /* Begin a successful frame; the handler may append DATA or ROW lines afterward. */
    response->length = 0;
    response->data[0] = '\0';
    response_line(response, "OK|%s\n", message);
}

static void clean_response(BankResponse *response) {
    /* Add END to handlers that have not done so; replace a nearly full frame safely. */
    if (response->length + 5 < sizeof(response->data)) response_end(response);
    else response_error(response, "Response was too large.");
}

static int write_all(int fd, const char *buffer, size_t length) {
    /*
     * Low-level counterpart to send_all(): write every byte to a file descriptor.
     * The caller gets -1 on a real write failure and must not commit a partial file.
     */
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, buffer + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        written += (size_t)count;
    }
    return 0;
}

static int parse_long_long(const char *text, long long *value) {
    /* Parse an entire signed decimal field (IDs/timestamps/balances), not a prefix. */
    if (!text || !*text) return -1;
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(text, &end, 10);
    if (errno || !end || *end) return -1;
    *value = parsed;
    return 0;
}

static int copy_field(char *destination, size_t capacity, const char *source, int allow_empty) {
    /*
     * Trim leading/trailing whitespace, then copy only if it fits. '|' separates
     * database/protocol columns, while control bytes could break line framing.
     * The destination is NUL-terminated on success; return -1 for invalid input.
     */
    if (!destination || !source || capacity == 0) return -1;
    const unsigned char *start = (const unsigned char *)source;
    while (*start && isspace(*start)) start++;
    const unsigned char *end = start + strlen((const char *)start);
    while (end > start && isspace(end[-1])) end--;
    size_t length = (size_t)(end - start);
    if ((!allow_empty && length == 0) || length >= capacity) return -1;
    for (size_t i = 0; i < length; i++) {
        if (start[i] < 32 || start[i] == 127 || start[i] == '|') return -1;
    }
    memcpy(destination, start, length);
    destination[length] = '\0';
    return 0;
}

static int normalize_username(const char *source, char destination[33]) {
    /*
     * Accept 3-32 letters/digits/dot/underscore/hyphen, requiring a letter or
     * digit first. Store lowercase so "Alice" and "alice" are one identity.
     */
    if (!source) return -1;
    size_t length = strlen(source);
    if (length < 3 || length > 32 || !isalnum((unsigned char)source[0])) return -1;
    for (size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)source[i];
        if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '.')) return -1;
        destination[i] = (char)tolower(ch);
    }
    destination[length] = '\0';
    return 0;
}

static int password_valid(const char *password, int new_password) {
    /*
     * Existing passwords may be shorter for seeded demo users; newly chosen
     * passwords need at least eight characters. Both are capped and cannot
     * contain protocol separators or control bytes.
     */
    if (!password) return 0;
    size_t length = strlen(password);
    if (length > 128 || (new_password && length < 8)) return 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)password[i];
        if (ch < 32 || ch == 127 || ch == '|') return 0;
    }
    return 1;
}

static int parse_amount(const char *text, long long *amount_paise) {
    /*
     * Accept positive rupee text such as "12", "12.3", or "12.34". Parse the
     * digits manually (never through float/double) and convert to paise exactly.
     * The overflow checks enforce MAX_AMOUNT_PAISE before multiplication.
     */
    if (!text || !*text) return -1;
    long long whole = 0;
    const char *cursor = text;
    if (!isdigit((unsigned char)*cursor)) return -1;
    while (isdigit((unsigned char)*cursor)) {
        int digit = *cursor++ - '0';
        if (whole > (MAX_AMOUNT_PAISE / 100 - digit) / 10) return -1;
        whole = whole * 10 + digit;
    }
    int cents = 0;
    if (*cursor == '.') {
        cursor++;
        if (!isdigit((unsigned char)*cursor)) return -1;
        cents = (*cursor++ - '0') * 10;
        if (isdigit((unsigned char)*cursor)) cents += *cursor++ - '0';
        if (isdigit((unsigned char)*cursor)) return -1;
    }
    if (*cursor != '\0' || whole > MAX_AMOUNT_PAISE / 100) return -1;
    long long result = whole * 100 + cents;
    if (result <= 0 || result > MAX_AMOUNT_PAISE) return -1;
    *amount_paise = result;
    return 0;
}

static void format_money(long long amount_paise, char output[48]) {
    /* Convert paise back to a display string, preserving sign and two decimal places. */
    long long absolute = amount_paise < 0 ? -amount_paise : amount_paise;
    snprintf(output, 48, "%s%lld.%02lld", amount_paise < 0 ? "-" : "",
             absolute / 100, absolute % 100);
}

static int hex_encode(const unsigned char *input, size_t length, char *output, size_t capacity) {
    /* Store binary salts/hashes/tokens as printable lowercase hex in bank.db. */
    static const char digits[] = "0123456789abcdef";
    if (capacity < length * 2 + 1) return -1;
    for (size_t i = 0; i < length; i++) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 15];
    }
    output[length * 2] = '\0';
    return 0;
}

static int hex_decode(const char *input, unsigned char *output, size_t output_length) {
    /* Reverse hex_encode(); reject the wrong width or any non-hexadecimal digit. */
    if (!input || strlen(input) != output_length * 2) return -1;
    for (size_t i = 0; i < output_length; i++) {
        int high = isdigit((unsigned char)input[i * 2]) ? input[i * 2] - '0' :
                   (tolower((unsigned char)input[i * 2]) - 'a' + 10);
        int low = isdigit((unsigned char)input[i * 2 + 1]) ? input[i * 2 + 1] - '0' :
                  (tolower((unsigned char)input[i * 2 + 1]) - 'a' + 10);
        if (high < 0 || high > 15 || low < 0 || low > 15) return -1;
        output[i] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int create_password_record(const char *password, char salt_hex[33], char hash_hex[65]) {
    /*
     * RAND_bytes supplies a unique salt for this password. PBKDF2 makes guessing
     * slower by repeatedly deriving SHA-256; only the salt and derived hash are
     * written to the database, never the original password.
     */
    unsigned char salt[16];
    unsigned char hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return -1;
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)sizeof(salt),
                          PASSWORD_ROUNDS, EVP_sha256(), (int)sizeof(hash), hash) != 1) return -1;
    return hex_encode(salt, sizeof(salt), salt_hex, 33) || hex_encode(hash, sizeof(hash), hash_hex, 65) ? -1 : 0;
}

static int password_matches(const char *password, const BankUser *user) {
    /* Re-derive the candidate with the saved salt, then compare without early exit. */
    unsigned char salt[16];
    unsigned char expected[32];
    unsigned char candidate[32];
    if (hex_decode(user->salt_hex, salt, sizeof(salt)) != 0 ||
        hex_decode(user->password_hash, expected, sizeof(expected)) != 0) return 0;
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)sizeof(salt),
                          PASSWORD_ROUNDS, EVP_sha256(), (int)sizeof(candidate), candidate) != 1) return 0;
    return CRYPTO_memcmp(expected, candidate, sizeof(candidate)) == 0;
}

static int split_fields(char *line, char **fields, size_t maximum) {
    /*
     * Replace each '|' with NUL and point fields[] at the pieces. The input line
     * is modified in place; return -1 if the fixed pointer array would overflow.
     */
    size_t count = 1;
    fields[0] = line;
    for (char *cursor = line; *cursor; cursor++) {
        if (*cursor == '|') {
            *cursor = '\0';
            if (count >= maximum) return -1;
            fields[count++] = cursor + 1;
        }
    }
    return (int)count;
}

static BankUser *find_user(BankState *state, const char *username) {
    /* Linear search is adequate for the project's fixed maximum of 128 users. */
    for (size_t i = 0; i < state->user_count; i++)
        if (strcmp(state->users[i].username, username) == 0) return &state->users[i];
    return NULL;
}

static BankAccount *find_account(BankState *state, const char *username) {
    /* Account ownership is keyed by username, so the first matching row is unique. */
    for (size_t i = 0; i < state->account_count; i++)
        if (strcmp(state->accounts[i].username, username) == 0) return &state->accounts[i];
    return NULL;
}

static BankUser *add_user(BankState *state, const char *username_source, const char *password,
                          const char *role, const char *name, const char *email, const char *phone,
                          char *error, size_t error_capacity);
static int add_transaction(BankState *state, const char *username, const char *type,
                           long long amount, const char *related, const char *reference,
                           const char *memo, BankTransaction **created);

static int load_database_record(BankState *state, char *line) {
    /*
     * Decode one pipe-separated database row. Record tags are META, USER,
     * ACCOUNT, TX, LOAN, FEEDBACK, and SESSION; each tag has a fixed field count.
     * A bad count, conversion, width, or capacity is an error rather than a row
     * to skip, because silently skipping it could corrupt later banking updates.
     */
    char *fields[16];
    int count = split_fields(line, fields, 16);
    if (count <= 0) return -1;
    /* META stores the next IDs, so identifiers stay unique after restart. */
    if (strcmp(fields[0], "META") == 0 && count == 5) {
        long long values[4];
        for (int i = 0; i < 4; i++) if (parse_long_long(fields[i + 1], &values[i]) != 0) return -1;
        state->next_account = (int)values[0];
        state->next_transaction = (int)values[1];
        state->next_loan = (int)values[2];
        state->next_feedback = (int)values[3];
    /* Each following tag reconstructs one typed record in the snapshot. */
    } else if (strcmp(fields[0], "USER") == 0 && count == 9 && state->user_count < BANK_MAX_USERS) {
        BankUser *item = &state->users[state->user_count++];
        if (copy_field(item->username, sizeof(item->username), fields[1], 0) ||
            copy_field(item->salt_hex, sizeof(item->salt_hex), fields[2], 0) ||
            copy_field(item->password_hash, sizeof(item->password_hash), fields[3], 0) ||
            copy_field(item->role, sizeof(item->role), fields[4], 0)) return -1;
        long long active = 0;
        if (parse_long_long(fields[5], &active) ||
            copy_field(item->name, sizeof(item->name), fields[6], 0) ||
            copy_field(item->email, sizeof(item->email), fields[7], 1) ||
            copy_field(item->phone, sizeof(item->phone), fields[8], 1)) return -1;
        item->active = active != 0;
    } else if (strcmp(fields[0], "ACCOUNT") == 0 && count == 5 && state->account_count < BANK_MAX_USERS) {
        BankAccount *item = &state->accounts[state->account_count++];
        if (copy_field(item->username, sizeof(item->username), fields[1], 0) ||
            copy_field(item->number, sizeof(item->number), fields[2], 0) ||
            parse_long_long(fields[3], &item->balance_paise) ||
            copy_field(item->status, sizeof(item->status), fields[4], 0)) return -1;
    } else if (strcmp(fields[0], "TX") == 0 && count == 10 && state->transaction_count < BANK_MAX_TRANSACTIONS) {
        BankTransaction *item = &state->transactions[state->transaction_count++];
        if (copy_field(item->id, sizeof(item->id), fields[1], 0) ||
            copy_field(item->username, sizeof(item->username), fields[2], 0) ||
            copy_field(item->type, sizeof(item->type), fields[3], 0) ||
            parse_long_long(fields[4], &item->amount_paise) ||
            parse_long_long(fields[5], &item->balance_after_paise) ||
            copy_field(item->related_account, sizeof(item->related_account), fields[6], 1) ||
            copy_field(item->reference, sizeof(item->reference), fields[7], 1) ||
            parse_long_long(fields[8], &item->created_at) ||
            copy_field(item->memo, sizeof(item->memo), fields[9], 1)) return -1;
    } else if (strcmp(fields[0], "LOAN") == 0 && count == 10 && state->loan_count < BANK_MAX_LOANS) {
        BankLoan *item = &state->loans[state->loan_count++];
        if (copy_field(item->id, sizeof(item->id), fields[1], 0) ||
            copy_field(item->username, sizeof(item->username), fields[2], 0) ||
            parse_long_long(fields[3], &item->amount_paise) ||
            copy_field(item->purpose, sizeof(item->purpose), fields[4], 0) ||
            copy_field(item->status, sizeof(item->status), fields[5], 0) ||
            copy_field(item->assigned_to, sizeof(item->assigned_to), fields[6], 1) ||
            copy_field(item->reviewed_by, sizeof(item->reviewed_by), fields[7], 1) ||
            parse_long_long(fields[8], &item->created_at) ||
            parse_long_long(fields[9], &item->reviewed_at)) return -1;
    } else if (strcmp(fields[0], "FEEDBACK") == 0 && count == 6 && state->feedback_count < BANK_MAX_FEEDBACK) {
        BankFeedback *item = &state->feedback[state->feedback_count++];
        long long reviewed = 0;
        if (copy_field(item->id, sizeof(item->id), fields[1], 0) ||
            copy_field(item->username, sizeof(item->username), fields[2], 0) ||
            copy_field(item->message, sizeof(item->message), fields[3], 0) ||
            parse_long_long(fields[4], &reviewed) || parse_long_long(fields[5], &item->created_at)) return -1;
        item->reviewed = reviewed != 0;
    } else if (strcmp(fields[0], "SESSION") == 0 && count == 5 && state->session_count < BANK_MAX_SESSIONS) {
        BankSessionRecord *item = &state->sessions[state->session_count++];
        long long pid = 0;
        if (copy_field(item->username, sizeof(item->username), fields[1], 0) ||
            copy_field(item->token, sizeof(item->token), fields[2], 0) ||
            parse_long_long(fields[3], &pid) || parse_long_long(fields[4], &item->last_seen)) return -1;
        item->worker_pid = (pid_t)pid;
    } else {
        return -1;
    }
    return 0;
}

static int load_database(const char *path, BankState *state) {
    /*
     * Load the current complete snapshot. A missing file means a new database;
     * malformed, oversized, or unreadable records fail closed instead of being
     * silently skipped and later overwritten.
     */
    state_reset(state);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    /* read() returns arbitrary chunks, so input[] is split into complete lines. */
    char input[4096];
    char line[4096];
    size_t used = 0;
    int result = 0;
    for (;;) {
        ssize_t count = read(fd, input, sizeof(input));
        if (count < 0) {
            if (errno == EINTR) continue;
            result = -1;
            break;
        }
        if (count == 0) break;
        /* Consume the chunk byte-by-byte, retaining a partial row across reads. */
        for (ssize_t i = 0; i < count; i++) {
            unsigned char ch = (unsigned char)input[i];
            if (ch == '\n') {
                /* A full row is now available; remove CR for CRLF files, then decode it. */
                if (used && line[used - 1] == '\r') used--;
                line[used] = '\0';
                if (load_database_record(state, line) != 0) { result = -1; break; }
                used = 0;
            } else if (ch == '\0' || used + 1 >= sizeof(line)) {
                result = -1;
                break;
            } else {
                line[used++] = (char)ch;
            }
        }
        if (result != 0) break;
    }
    if (result == 0 && used > 0) {
        if (line[used - 1] == '\r') used--;
        line[used] = '\0';
        if (load_database_record(state, line) != 0) result = -1;
    }
    if (close(fd) != 0) result = -1;
    return result;
}

static int save_database(const char *data_dir, const char *path, const BankState *state) {
    /*
     * Serialize to a unique file in the same directory, sync its contents, then
     * rename it over the database. Same-directory rename makes readers observe
     * either the old complete snapshot or the new complete snapshot, never a
     * partially written database. Syncing the directory strengthens durability
     * by persisting the rename metadata after the file contents have been synced.
     */
    /* A unique temporary filename avoids colliding with another writer's scratch file. */
    char temporary[PATH_MAX];
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    if (snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%ld", path, (long)getpid(), now.tv_nsec) >= (int)sizeof(temporary)) return -1;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    char line[4096];
    int failed = 0;
/* Stop at the first formatting/write error; never rename an incomplete snapshot. */
#define WRITE_LINE(...) do { \
    int size = snprintf(line, sizeof(line), __VA_ARGS__); \
    if (size < 0 || (size_t)size >= sizeof(line) || write_all(fd, line, (size_t)size) != 0) failed = 1; \
    if (failed) goto save_done; \
} while (0)
    /* Write records in a fixed format that load_database_record() understands. */
    WRITE_LINE("META|%d|%d|%d|%d\n", state->next_account, state->next_transaction, state->next_loan, state->next_feedback);
    for (size_t i = 0; i < state->user_count; i++) {
        const BankUser *item = &state->users[i];
        WRITE_LINE("USER|%s|%s|%s|%s|%d|%s|%s|%s\n", item->username, item->salt_hex, item->password_hash,
                   item->role, item->active, item->name, item->email, item->phone);
    }
    for (size_t i = 0; i < state->account_count; i++) {
        const BankAccount *item = &state->accounts[i];
        WRITE_LINE("ACCOUNT|%s|%s|%lld|%s\n", item->username, item->number, item->balance_paise, item->status);
    }
    for (size_t i = 0; i < state->transaction_count; i++) {
        const BankTransaction *item = &state->transactions[i];
        WRITE_LINE("TX|%s|%s|%s|%lld|%lld|%s|%s|%lld|%s\n", item->id, item->username, item->type,
                   item->amount_paise, item->balance_after_paise, item->related_account, item->reference,
                   item->created_at, item->memo);
    }
    for (size_t i = 0; i < state->loan_count; i++) {
        const BankLoan *item = &state->loans[i];
        WRITE_LINE("LOAN|%s|%s|%lld|%s|%s|%s|%s|%lld|%lld\n", item->id, item->username,
                   item->amount_paise, item->purpose, item->status, item->assigned_to,
                   item->reviewed_by, item->created_at, item->reviewed_at);
    }
    for (size_t i = 0; i < state->feedback_count; i++) {
        const BankFeedback *item = &state->feedback[i];
        WRITE_LINE("FEEDBACK|%s|%s|%s|%d|%lld\n", item->id, item->username, item->message,
                   item->reviewed, item->created_at);
    }
    for (size_t i = 0; i < state->session_count; i++) {
        const BankSessionRecord *item = &state->sessions[i];
        WRITE_LINE("SESSION|%s|%s|%ld|%lld\n", item->username, item->token,
                   (long)item->worker_pid, item->last_seen);
    }
save_done:
#undef WRITE_LINE
    /* Flush file contents before rename, then close before replacing bank.db. */
    if (!failed && fsync(fd) != 0) failed = 1;
    if (close(fd) != 0) failed = 1;
    if (failed) {
        unlink(temporary);
        return -1;
    }
    /* rename() is atomic on the same filesystem, so readers never see a partial DB. */
    if (rename(temporary, path) != 0) { unlink(temporary); return -1; }
    int directory_fd = open(data_dir, O_RDONLY | O_DIRECTORY);
    if (directory_fd >= 0) {
        if (fsync(directory_fd) != 0) { close(directory_fd); return -1; }
        close(directory_fd);
    }
    return 0;
}

static int lock_database(BankStore *store, int *lock_fd) {
    /*
     * Acquire the semaphore first for threads and workers in this server process.
     * flock() on a stable sidecar file also coordinates a second server process
     * pointed at the same data directory (each process has its own semaphore).
     */
    while (sem_wait(store->database_semaphore) != 0) if (errno != EINTR) return -1;
    *lock_fd = open(store->lock_path, O_CREAT | O_RDWR, 0600);
    if (*lock_fd < 0) { sem_post(store->database_semaphore); return -1; }
    while (flock(*lock_fd, LOCK_EX) != 0) {
        if (errno == EINTR) continue;
        close(*lock_fd);
        sem_post(store->database_semaphore);
        return -1;
    }
    return 0;
}

static void unlock_database(BankStore *store, int lock_fd) {
    /* Release both layers of exclusion after the read/validate/commit sequence. */
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    sem_post(store->database_semaphore);
}

static int run_locked(BankStore *store, StateOperation operation, void *context,
                      BankResponse *response) {
    /*
     * Every state-changing or state-reading request uses this transaction shell:
     * acquire locks, load the latest file, run one operation, save if changed,
     * then release resources. A failed load never reaches the operation callback.
     */
    BankState *state = calloc(1, sizeof(*state));
    if (!state) { response_error(response, "Server memory is unavailable."); return -1; }
    int lock_fd = -1;
    if (lock_database(store, &lock_fd) != 0) {
        free(state);
        response_error(response, "Could not lock the banking database.");
        return -1;
    }
    int result = load_database(store->database_path, state);
    if (result != 0) {
        response_error(response, "Banking database is damaged or unreadable.");
        unlock_database(store, lock_fd);
        free(state);
        return -1;
    }
    /* Callback result 0 means no database write; nonzero means save its changes. */
    int changed = operation(state, context);
    if (changed && save_database(store->data_dir, store->database_path, state) != 0) {
        response_error(response, "Could not commit the banking operation.");
        result = -1;
    }
    unlock_database(store, lock_fd);
    free(state);
    return result;
}

static int add_account(BankState *state, const char *username, long long balance, BankAccount **created) {
    /*
     * Append an account to the next free array slot. The username must already
     * identify a user; the caller validates that relationship. created is an
     * optional output pointer when the caller needs the new account immediately.
     */
    if (state->account_count >= BANK_MAX_USERS) return -1;
    BankAccount *item = &state->accounts[state->account_count++];
    memset(item, 0, sizeof(*item));
    snprintf(item->username, sizeof(item->username), "%s", username);
    snprintf(item->number, sizeof(item->number), "AC%08d", state->next_account++);
    item->balance_paise = balance;
    snprintf(item->status, sizeof(item->status), "ACTIVE");
    if (created) *created = item;
    return 0;
}

static BankUser *add_user(BankState *state, const char *username_source, const char *password,
                          const char *role, const char *name, const char *email, const char *phone,
                          char *error, size_t error_capacity) {
    /*
     * Create an identity only after validating every input and deriving its
     * password hash. For customer role, also create a zero-balance account.
     * Return a pointer into state->users, or NULL and a human-readable error.
     */
    char username[33];
    if (normalize_username(username_source, username) != 0) {
        snprintf(error, error_capacity, "Username must be 3-32 characters and use letters, digits, dot, underscore, or hyphen.");
        return NULL;
    }
    if (find_user(state, username)) { snprintf(error, error_capacity, "That username is already in use."); return NULL; }
    if (!password_valid(password, 1)) { snprintf(error, error_capacity, "Password must be 8-128 characters without control characters or the pipe symbol."); return NULL; }
    if (state->user_count >= BANK_MAX_USERS) { snprintf(error, error_capacity, "The user limit has been reached."); return NULL; }
    if (strcmp(role, "customer") && strcmp(role, "employee") && strcmp(role, "manager") && strcmp(role, "administrator")) {
        snprintf(error, error_capacity, "The requested user role is invalid."); return NULL;
    }
    BankUser *item = &state->users[state->user_count];
    memset(item, 0, sizeof(*item));
    if (copy_field(item->name, sizeof(item->name), name, 0) ||
        copy_field(item->email, sizeof(item->email), email, 1) ||
        copy_field(item->phone, sizeof(item->phone), phone, 1)) {
        snprintf(error, error_capacity, "Name or contact details are invalid."); return NULL;
    }
    snprintf(item->username, sizeof(item->username), "%s", username);
    snprintf(item->role, sizeof(item->role), "%s", role);
    item->active = 1;
    if (create_password_record(password, item->salt_hex, item->password_hash) != 0) {
        snprintf(error, error_capacity, "Could not create a password hash."); return NULL;
    }
    /* The user becomes part of the valid array only after all user fields are ready. */
    state->user_count++;
    if (!strcmp(role, "customer") && add_account(state, username, 0, NULL) != 0) {
        state->user_count--;
        snprintf(error, error_capacity, "Could not create the customer account."); return NULL;
    }
    return item;
}

static int add_transaction(BankState *state, const char *username, const char *type,
                           long long amount, const char *related, const char *reference,
                           const char *memo, BankTransaction **created) {
    /*
     * Append one ledger row. Callers change the account balance first so this
     * function captures the after-balance. This does not write the file itself;
     * run_locked() commits the row together with all other state changes.
     */
    if (state->transaction_count >= BANK_MAX_TRANSACTIONS) return -1;
    BankAccount *account = find_account(state, username);
    if (!account) return -1;
    BankTransaction *item = &state->transactions[state->transaction_count++];
    memset(item, 0, sizeof(*item));
    snprintf(item->id, sizeof(item->id), "TX%07d", state->next_transaction++);
    snprintf(item->username, sizeof(item->username), "%s", username);
    snprintf(item->type, sizeof(item->type), "%s", type);
    item->amount_paise = amount;
    item->balance_after_paise = account->balance_paise;
    snprintf(item->related_account, sizeof(item->related_account), "%s", related ? related : "");
    snprintf(item->reference, sizeof(item->reference), "%s", reference ? reference : "");
    item->created_at = (long long)time(NULL);
    snprintf(item->memo, sizeof(item->memo), "%s", memo ? memo : "");
    if (created) *created = item;
    return 0;
}

int bank_store_init(BankStore *store, const char *data_dir, sem_t *database_semaphore) {
    /*
     * Prepare a store handle shared with all workers. Create the directory if
     * needed, lock it while examining bank.db, seed demo records if absent, or
     * parse an existing file to fail early if it is damaged.
     */
    if (!store || !data_dir || !database_semaphore) return -1;
    memset(store, 0, sizeof(*store));
    if (snprintf(store->data_dir, sizeof(store->data_dir), "%s", data_dir) >= (int)sizeof(store->data_dir) ||
        snprintf(store->database_path, sizeof(store->database_path), "%s/bank.db", data_dir) >= (int)sizeof(store->database_path) ||
        snprintf(store->lock_path, sizeof(store->lock_path), "%s/bank.lock", data_dir) >= (int)sizeof(store->lock_path)) return -1;
    store->database_semaphore = database_semaphore;
    if (mkdir(data_dir, 0700) != 0 && errno != EEXIST) return -1;
    int lock_fd = -1;
    if (lock_database(store, &lock_fd) != 0) return -1;
    int result = 0;
    if (access(store->database_path, F_OK) != 0) {
        /* First run: create demo users and Alice's opening balance transaction. */
        BankState *state = calloc(1, sizeof(*state));
        if (!state) result = -1;
        else {
            state_reset(state);
            char error[256];
            if (!add_user(state, "admin", "admin123", "administrator", "Demo Administrator", "admin@example.test", "", error, sizeof(error)) ||
                !add_user(state, "manager", "manager123", "manager", "Demo Manager", "manager@example.test", "", error, sizeof(error)) ||
                !add_user(state, "employee", "employee123", "employee", "Demo Employee", "employee@example.test", "", error, sizeof(error)) ||
                !add_user(state, "alice", "alice123", "customer", "Alice Sample", "alice@example.test", "9000000001", error, sizeof(error))) result = -1;
            if (result == 0) {
                BankAccount *alice = find_account(state, "alice");
                alice->balance_paise = 2500000;
                if (add_transaction(state, "alice", "OPENING_BALANCE", 2500000, "", "", "Demo account opening", NULL) != 0 ||
                    save_database(store->data_dir, store->database_path, state) != 0) result = -1;
            }
            free(state);
        }
    } else {
        BankState *state = calloc(1, sizeof(*state));
        if (!state || load_database(store->database_path, state) != 0) result = -1;
        free(state);
    }
    unlock_database(store, lock_fd);
    return result;
}

static BankSessionRecord *find_session(BankState *state, const char *username) {
    /* Sessions are unique by username; NULL means this user is not signed in. */
    for (size_t i = 0; i < state->session_count; i++)
        if (strcmp(state->sessions[i].username, username) == 0) return &state->sessions[i];
    return NULL;
}

static void remove_session(BankState *state, size_t index) {
    /* Compact the bounded session array so its count always describes live entries. */
    if (index >= state->session_count) return;
    if (index + 1 < state->session_count)
        memmove(&state->sessions[index], &state->sessions[index + 1],
                (state->session_count - index - 1) * sizeof(state->sessions[0]));
    state->session_count--;
    memset(&state->sessions[state->session_count], 0, sizeof(state->sessions[0]));
}

static int process_is_alive(pid_t pid) {
    /* kill(pid, 0) checks process existence without sending a signal. */
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno != ESRCH;
}

static int role_is(const BankUser *user, const char *role) {
    /* Guard against a missing user before comparing role text. */
    return user && strcmp(user->role, role) == 0;
}

static int role_allowed(const BankUser *user, const char *a, const char *b,
                        const char *c) {
    /* Shared role-list check; individual commands still define their permitted roles. */
    return user && ((!a || strcmp(user->role, a) == 0) ||
                    (b && strcmp(user->role, b) == 0) ||
                    (c && strcmp(user->role, c) == 0));
}

static int expect_count(RequestContext *context, size_t expected) {
    /* Each command has a fixed number of pipe-separated fields; fail before indexing them. */
    if (context->count == expected) return 0;
    response_error(context->response, "The command has the wrong number of fields.");
    return -1;
}

static int get_username(const char *source, char output[33]) {
    /* Keep all request paths using the same canonical username rules. */
    return normalize_username(source, output);
}

static int create_session_token(char token[65]) {
    /* A random 256-bit token prevents another connection from claiming this session. */
    unsigned char bytes[32];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) return -1;
    return hex_encode(bytes, sizeof(bytes), token, 65);
}

static int login_operation(BankState *state, void *argument) {
    /*
     * Expire stale records, authenticate the user, enforce one active session,
     * and save a random session token tied to the worker process.
     */
    RequestContext *context = argument;
    BankResponse *response = context->response;
    if (expect_count(context, 3) != 0) return 0;
    char username[33];
    const char *password = context->fields[2];
    if (get_username(context->fields[1], username) != 0 || !password_valid(password, 0)) {
        response_error(response, "Invalid username or password.");
        return 0;
    }
    /* Remove expired sessions in-place; do not increment after shifting a row left. */
    long long now = (long long)time(NULL);
    for (size_t i = 0; i < state->session_count;) {
        BankSessionRecord *record = &state->sessions[i];
        if (now - record->last_seen > SESSION_LIFETIME || !process_is_alive(record->worker_pid)) remove_session(state, i);
        else i++;
    }
    /* Password checking happens only after lookup; inactive users get no session. */
    BankUser *user = find_user(state, username);
    if (!user || !user->active || !password_matches(password, user)) {
        response_error(response, "Invalid username or password, or the user is inactive.");
        return 1;
    }
    BankAccount *account = find_account(state, username);
    if (role_is(user, "customer") && (!account || strcmp(account->status, "ACTIVE") != 0)) {
        response_error(response, "This customer account is inactive. Contact a bank manager.");
        return 1;
    }
    /* This check is protected by run_locked(), so two simultaneous logins cannot win. */
    if (find_session(state, username)) {
        response_error(response, "This user already has an active session.");
        return 1;
    }
    if (state->session_count >= BANK_MAX_SESSIONS) {
        response_error(response, "The active session limit has been reached.");
        return 1;
    }
    /* Store the token in the shared database and in this thread's local session. */
    BankSessionRecord *record = &state->sessions[state->session_count];
    memset(record, 0, sizeof(*record));
    if (create_session_token(record->token) != 0) {
        response_error(response, "Could not create a session token.");
        return 1;
    }
    snprintf(record->username, sizeof(record->username), "%s", username);
    record->worker_pid = getpid();
    record->last_seen = now;
    state->session_count++;
    context->session->authenticated = 1;
    snprintf(context->session->username, sizeof(context->session->username), "%s", username);
    snprintf(context->session->token, sizeof(context->session->token), "%s", record->token);
    response_line(response, "OK|%s|%s\n", user->role, user->name);
    return 1;
}

static int account_active(BankState *state, const char *username, BankAccount **account_out) {
    /* Return 1 only for ACTIVE accounts; optionally give the caller its state row. */
    BankAccount *account = find_account(state, username);
    if (!account || strcmp(account->status, "ACTIVE") != 0) return 0;
    if (account_out) *account_out = account;
    return 1;
}

static int account_for_customer(BankState *state, const char *username, BankAccount **account_out) {
    /* A transfer recipient must be both a customer user and an active account owner. */
    BankUser *user = find_user(state, username);
    if (!user || !role_is(user, "customer") || !account_active(state, username, account_out)) return 0;
    return 1;
}

static BankLoan *find_loan(BankState *state, const char *id) {
    /* Find a loan by its generated LN... identifier; NULL means not found. */
    for (size_t i = 0; i < state->loan_count; i++)
        if (strcmp(state->loans[i].id, id) == 0) return &state->loans[i];
    return NULL;
}

static void loan_row(BankResponse *response, BankState *state, const BankLoan *loan) {
    /* Format one protocol ROW; look up names for display but retain usernames as keys. */
    BankUser *customer = find_user(state, loan->username);
    BankUser *employee = loan->assigned_to[0] ? find_user(state, loan->assigned_to) : NULL;
    char amount[48];
    format_money(loan->amount_paise, amount);
    response_line(response, "ROW|%s|%s|%s|%s|%s|%s|%s\n", loan->id, loan->username,
                  customer ? customer->name : "", amount, loan->purpose, loan->status,
                  employee ? employee->username : "");
}

static void transaction_row(BankResponse *response, const BankTransaction *item) {
    /* Format one passbook ROW using rupees for display while storage remains paise. */
    char amount[48], balance[48];
    format_money(item->amount_paise, amount);
    format_money(item->balance_after_paise, balance);
    response_line(response, "ROW|%s|%s|%s|%s|%s|%s|%lld|%s\n", item->id, item->type,
                  amount, balance, item->related_account, item->reference,
                  item->created_at, item->memo);
}

static int add_loan(BankState *state, const char *username, long long amount,
                    const char *purpose, BankLoan **created) {
    /* Append a PENDING application; manager assignment and employee decision follow later. */
    if (state->loan_count >= BANK_MAX_LOANS) return -1;
    BankLoan *loan = &state->loans[state->loan_count++];
    memset(loan, 0, sizeof(*loan));
    snprintf(loan->id, sizeof(loan->id), "LN%07d", state->next_loan++);
    snprintf(loan->username, sizeof(loan->username), "%s", username);
    loan->amount_paise = amount;
    snprintf(loan->purpose, sizeof(loan->purpose), "%s", purpose);
    snprintf(loan->status, sizeof(loan->status), "PENDING");
    loan->created_at = (long long)time(NULL);
    if (created) *created = loan;
    return 0;
}

static int add_feedback(BankState *state, const char *username, const char *message,
                        BankFeedback **created) {
    /* Append feedback; the manager review command changes its reviewed flag later. */
    if (state->feedback_count >= BANK_MAX_FEEDBACK) return -1;
    BankFeedback *feedback = &state->feedback[state->feedback_count++];
    memset(feedback, 0, sizeof(*feedback));
    snprintf(feedback->id, sizeof(feedback->id), "FB%07d", state->next_feedback++);
    snprintf(feedback->username, sizeof(feedback->username), "%s", username);
    snprintf(feedback->message, sizeof(feedback->message), "%s", message);
    feedback->created_at = (long long)time(NULL);
    if (created) *created = feedback;
    return 0;
}

static void dispatch_command(BankState *state, RequestContext *context, BankUser *user) {
    /*
     * Route an authenticated request only after the session gate has loaded the
     * current user record. Each branch checks its role and input shape again;
     * hiding a menu option is never treated as authorization.
     *
     * Branch pattern: verify argument count, verify role, parse arguments,
     * check the current snapshot's business rules, then build a response. Any
     * successful mutation is saved by run_locked() after this function returns.
     */
    BankResponse *response = context->response;
    char username[33];
    long long amount = 0;
    const char *command = context->fields[0];

    /* BALANCE: no arguments; return the signed-in customer's account summary. */
    if (strcmp(command, "BALANCE") == 0) {
        if (expect_count(context, 1)) return;
        if (!role_is(user, "customer")) { response_error(response, "Only customers can view this balance."); return; }
        BankAccount *account = find_account(state, user->username);
        if (!account) { response_error(response, "Customer account was not found."); return; }
        char balance[48]; format_money(account->balance_paise, balance);
        response_ok(response, "Account summary.");
        response_line(response, "DATA|%s|%s|%s\n", account->number, account->status, balance);
        return;
    }

    /* DEPOSIT|amount and WITHDRAW|amount share parsing and account checks. */
    if (strcmp(command, "DEPOSIT") == 0 || strcmp(command, "WITHDRAW") == 0) {
        int is_deposit = strcmp(command, "DEPOSIT") == 0;
        if (expect_count(context, 2)) return;
        if (!role_is(user, "customer")) { response_error(response, "Only customers can deposit or withdraw money."); return; }
        if (parse_amount(context->fields[1], &amount) != 0) { response_error(response, "Enter a positive amount with up to two decimal places."); return; }
        BankAccount *account = NULL;
        if (!account_active(state, user->username, &account)) { response_error(response, "This account is inactive."); return; }
        if (is_deposit && account->balance_paise > LLONG_MAX - amount) { response_error(response, "This deposit would exceed the account balance limit."); return; }
        if (!is_deposit && account->balance_paise < amount) { response_error(response, "There are not enough funds for this withdrawal."); return; }
        if (state->transaction_count >= BANK_MAX_TRANSACTIONS) { response_error(response, "The transaction history limit has been reached."); return; }
        /* Balance and ledger entry are changed in the same locked snapshot. */
        account->balance_paise += is_deposit ? amount : -amount;
        BankTransaction *item = NULL;
        if (add_transaction(state, user->username, is_deposit ? "DEPOSIT" : "WITHDRAW", amount, "", "", "Customer initiated", &item) != 0) {
            response_error(response, "Could not record the transaction."); return;
        }
        char balance[48]; format_money(account->balance_paise, balance);
        response_ok(response, is_deposit ? "Deposit completed." : "Withdrawal completed.");
        response_line(response, "DATA|%s|%s\n", item->id, balance);
        return;
    }

    /* TRANSFER|recipient|amount moves funds between two active customer accounts. */
    if (strcmp(command, "TRANSFER") == 0) {
        if (expect_count(context, 3)) return;
        if (!role_is(user, "customer")) { response_error(response, "Only customers can transfer funds."); return; }
        if (get_username(context->fields[1], username) != 0 || parse_amount(context->fields[2], &amount) != 0) {
            response_error(response, "Enter a valid recipient and positive amount."); return;
        }
        if (!strcmp(username, user->username)) { response_error(response, "Choose a different destination account."); return; }
        BankAccount *sender = NULL, *recipient = NULL;
        if (!account_active(state, user->username, &sender) || !account_for_customer(state, username, &recipient)) {
            response_error(response, "An active customer destination account was not found."); return;
        }
        if (sender->balance_paise < amount) { response_error(response, "There are not enough funds for this transfer."); return; }
        if (recipient->balance_paise > LLONG_MAX - amount) { response_error(response, "This transfer would exceed the destination account balance limit."); return; }
        if (state->transaction_count + 2 > BANK_MAX_TRANSACTIONS) { response_error(response, "The transaction history limit has been reached."); return; }
        char reference[20];
        snprintf(reference, sizeof(reference), "TR%07d", state->next_transaction++);
        /* Debit, credit, and both ledger rows commit together in run_locked(). */
        sender->balance_paise -= amount;
        recipient->balance_paise += amount;
        if (add_transaction(state, user->username, "TRANSFER_OUT", amount, recipient->number, reference, "", NULL) != 0 ||
            add_transaction(state, username, "TRANSFER_IN", amount, sender->number, reference, "", NULL) != 0) {
            response_error(response, "Could not record both sides of the transfer."); return;
        }
        response_ok(response, "Transfer completed.");
        response_line(response, "DATA|%s\n", reference);
        return;
    }

    /* LOAN_APPLY|amount|purpose creates work for the manager/employee workflow. */
    if (strcmp(command, "LOAN_APPLY") == 0) {
        if (expect_count(context, 3)) return;
        if (!role_is(user, "customer")) { response_error(response, "Only customers can apply for loans."); return; }
        if (parse_amount(context->fields[1], &amount) != 0) { response_error(response, "Enter a valid positive loan amount."); return; }
        char purpose[241];
        if (copy_field(purpose, sizeof(purpose), context->fields[2], 0)) { response_error(response, "Loan purpose must be 1-240 characters without control characters or pipes."); return; }
        if (!account_active(state, user->username, NULL)) { response_error(response, "This account is inactive."); return; }
        BankLoan *loan = NULL;
        if (add_loan(state, user->username, amount, purpose, &loan) != 0) { response_error(response, "The loan application limit has been reached."); return; }
        response_ok(response, "Loan application submitted for review.");
        response_line(response, "DATA|%s\n", loan->id);
        return;
    }

    /* CHANGE_PASSWORD|current|new verifies the old secret before replacing its hash. */
    if (strcmp(command, "CHANGE_PASSWORD") == 0) {
        if (expect_count(context, 3)) return;
        if (!password_valid(context->fields[1], 0) || !password_valid(context->fields[2], 1)) {
            response_error(response, "New password must be 8-128 characters; passwords cannot contain controls or pipes."); return;
        }
        if (!password_matches(context->fields[1], user)) { response_error(response, "Current password is incorrect."); return; }
        if (create_password_record(context->fields[2], user->salt_hex, user->password_hash) != 0) {
            response_error(response, "Could not create a password hash."); return;
        }
        response_ok(response, "Password changed.");
        return;
    }

    /* FEEDBACK_ADD|message lets a customer leave a reviewable message. */
    if (strcmp(command, "FEEDBACK_ADD") == 0) {
        if (expect_count(context, 2)) return;
        if (!role_is(user, "customer")) { response_error(response, "Only customers can submit feedback."); return; }
        char message[1001];
        if (copy_field(message, sizeof(message), context->fields[1], 0)) { response_error(response, "Feedback must be 1-1000 characters without control characters or pipes."); return; }
        BankFeedback *feedback = NULL;
        if (add_feedback(state, user->username, message, &feedback) != 0) { response_error(response, "The feedback limit has been reached."); return; }
        response_ok(response, "Feedback submitted.");
        response_line(response, "DATA|%s\n", feedback->id);
        return;
    }

    /* HISTORY optionally takes a username; staff can inspect another passbook. */
    if (strcmp(command, "HISTORY") == 0) {
        const char *target = user->username;
        if (context->count == 2) {
            if (!role_allowed(user, "employee", "manager", "administrator")) { response_error(response, "Your role cannot view another customer's passbook."); return; }
            if (get_username(context->fields[1], username) != 0) { response_error(response, "Customer username is invalid."); return; }
            target = username;
        } else if (context->count != 1) { response_error(response, "The history command has the wrong number of fields."); return; }
        if (!role_is(user, "customer") && context->count == 1) { response_error(response, "Enter a customer username to view a passbook."); return; }
        if (!find_account(state, target)) { response_error(response, "Customer account was not found."); return; }
        response_ok(response, "Recent transaction history.");
        size_t shown = 0;
        for (size_t i = state->transaction_count; i > 0 && shown < 100; i--) {
            BankTransaction *item = &state->transactions[i - 1];
            if (!strcmp(item->username, target)) { transaction_row(response, item); shown++; }
        }
        return;
    }

    /* CUSTOMER_ADD|username|password|name|email|phone opens a customer account. */
    if (strcmp(command, "CUSTOMER_ADD") == 0) {
        if (expect_count(context, 6)) return;
        if (!role_allowed(user, "employee", "administrator", NULL)) { response_error(response, "Only employees or administrators can open customer accounts."); return; }
        char error[256];
        BankUser *created = add_user(state, context->fields[1], context->fields[2], "customer",
                                     context->fields[3], context->fields[4], context->fields[5], error, sizeof(error));
        if (!created) { response_error(response, error); return; }
        BankAccount *account = find_account(state, created->username);
        response_ok(response, "Customer and account created.");
        response_line(response, "DATA|%s|%s\n", created->username, account ? account->number : "");
        return;
    }

    /* USER_MODIFY|username|name|email|phone updates only fields supplied as nonblank. */
    if (strcmp(command, "USER_MODIFY") == 0) {
        if (expect_count(context, 5)) return;
        if (!role_allowed(user, "employee", "administrator", NULL)) { response_error(response, "Only employees or administrators can modify customer details."); return; }
        if (get_username(context->fields[1], username) != 0) { response_error(response, "Username is invalid."); return; }
        BankUser *target = find_user(state, username);
        if (!target) { response_error(response, "User account was not found."); return; }
        if (role_is(user, "employee") && !role_is(target, "customer")) { response_error(response, "Employees can modify customer details only."); return; }
        if (role_is(user, "administrator") && !role_allowed(target, "customer", "employee", NULL)) { response_error(response, "Administrators can modify customer and employee details here."); return; }
        char new_name[101] = "", new_email[161] = "", new_phone[41] = "";
        if ((context->fields[2][0] && copy_field(new_name, sizeof(new_name), context->fields[2], 0)) ||
            (context->fields[3][0] && copy_field(new_email, sizeof(new_email), context->fields[3], 1)) ||
            (context->fields[4][0] && copy_field(new_phone, sizeof(new_phone), context->fields[4], 1))) {
            response_error(response, "One or more user details are invalid."); return;
        }
        if (new_name[0]) snprintf(target->name, sizeof(target->name), "%s", new_name);
        if (context->fields[3][0]) snprintf(target->email, sizeof(target->email), "%s", new_email);
        if (context->fields[4][0]) snprintf(target->phone, sizeof(target->phone), "%s", new_phone);
        response_ok(response, "User details updated.");
        response_line(response, "DATA|%s|%s|%s|%s\n", target->username, target->name, target->email, target->phone);
        return;
    }

    /* List commands take no arguments and show only work allowed for the caller's role. */
    if (strcmp(command, "LOANS_ASSIGNED") == 0 || strcmp(command, "LOANS_UNASSIGNED") == 0) {
        int assigned = strcmp(command, "LOANS_ASSIGNED") == 0;
        if (expect_count(context, 1)) return;
        if (assigned && !role_is(user, "employee")) { response_error(response, "Only employees can view assigned applications."); return; }
        if (!assigned && !role_is(user, "manager")) { response_error(response, "Only managers can view unassigned applications."); return; }
        response_ok(response, assigned ? "Assigned loan applications." : "Unassigned loan applications.");
        size_t shown = 0;
        for (size_t i = 0; i < state->loan_count && shown < 100; i++) {
            BankLoan *loan = &state->loans[i];
            if ((assigned && !strcmp(loan->assigned_to, user->username) && !strcmp(loan->status, "ASSIGNED")) ||
                (!assigned && !strcmp(loan->status, "PENDING"))) { loan_row(response, state, loan); shown++; }
        }
        return;
    }

    /* LOAN_ASSIGN|loan_id|employee changes a pending application to ASSIGNED. */
    if (strcmp(command, "LOAN_ASSIGN") == 0) {
        if (expect_count(context, 3)) return;
        if (!role_is(user, "manager")) { response_error(response, "Only managers can assign loans."); return; }
        char loan_id[20];
        if (copy_field(loan_id, sizeof(loan_id), context->fields[1], 0) || get_username(context->fields[2], username) != 0) {
            response_error(response, "Loan ID or employee username is invalid."); return;
        }
        BankUser *employee = find_user(state, username);
        if (!employee || !role_is(employee, "employee") || !employee->active) { response_error(response, "Choose an active employee account."); return; }
        BankLoan *loan = find_loan(state, loan_id);
        if (!loan || strcmp(loan->status, "PENDING") != 0) { response_error(response, "That loan is not available for assignment."); return; }
        snprintf(loan->assigned_to, sizeof(loan->assigned_to), "%s", username);
        snprintf(loan->status, sizeof(loan->status), "ASSIGNED");
        response_ok(response, "Loan assigned.");
        response_line(response, "DATA|%s|%s\n", loan->id, username);
        return;
    }

    /* LOAN_DECIDE|loan_id|approve-or-reject is restricted to its assigned employee. */
    if (strcmp(command, "LOAN_DECIDE") == 0) {
        if (expect_count(context, 3)) return;
        if (!role_is(user, "employee")) { response_error(response, "Only employees can process loan applications."); return; }
        char loan_id[20], decision[16];
        if (copy_field(loan_id, sizeof(loan_id), context->fields[1], 0) || copy_field(decision, sizeof(decision), context->fields[2], 0)) {
            response_error(response, "Loan ID or decision is invalid."); return;
        }
        for (char *p = decision; *p; p++) *p = (char)toupper((unsigned char)*p);
        if (strcmp(decision, "APPROVE") && strcmp(decision, "REJECT")) { response_error(response, "Decision must be APPROVE or REJECT."); return; }
        BankLoan *loan = find_loan(state, loan_id);
        if (!loan || strcmp(loan->assigned_to, user->username) || strcmp(loan->status, "ASSIGNED")) {
            response_error(response, "That application is not assigned to you or has already been processed."); return;
        }
        BankAccount *customer_account = NULL;
        if (!strcmp(decision, "APPROVE")) {
            if (!account_active(state, loan->username, &customer_account)) { response_error(response, "The customer account is inactive; reactivate it before approval."); return; }
            if (state->transaction_count >= BANK_MAX_TRANSACTIONS) { response_error(response, "The transaction history limit has been reached."); return; }
            if (customer_account->balance_paise > LLONG_MAX - loan->amount_paise) { response_error(response, "This loan would exceed the customer account balance limit."); return; }
            /* Approval disburses funds and records its audit row in one snapshot. */
            customer_account->balance_paise += loan->amount_paise;
            if (add_transaction(state, loan->username, "LOAN_DISBURSEMENT", loan->amount_paise, "", loan->id, loan->id, NULL) != 0) {
                customer_account->balance_paise -= loan->amount_paise;
                response_error(response, "Could not record the loan disbursement."); return;
            }
            snprintf(loan->status, sizeof(loan->status), "APPROVED");
        } else snprintf(loan->status, sizeof(loan->status), "REJECTED");
        snprintf(loan->reviewed_by, sizeof(loan->reviewed_by), "%s", user->username);
        loan->reviewed_at = (long long)time(NULL);
        response_ok(response, "Loan decision saved.");
        response_line(response, "DATA|%s|%s\n", loan->id, loan->status);
        return;
    }

    /* ACCOUNT_STATUS|username|active-or-inactive cannot reopen a CLOSED account. */
    if (strcmp(command, "ACCOUNT_STATUS") == 0) {
        if (expect_count(context, 3)) return;
        if (!role_is(user, "manager")) { response_error(response, "Only managers can change customer account status."); return; }
        if (get_username(context->fields[1], username) != 0) { response_error(response, "Customer username is invalid."); return; }
        BankUser *target = find_user(state, username);
        BankAccount *account = find_account(state, username);
        if (!target || !role_is(target, "customer") || !account) { response_error(response, "Customer account was not found."); return; }
        if (!strcmp(account->status, "CLOSED")) { response_error(response, "A closed account cannot be reactivated or changed."); return; }
        char status[12];
        if (copy_field(status, sizeof(status), context->fields[2], 0)) { response_error(response, "Account status is invalid."); return; }
        for (char *p = status; *p; p++) *p = (char)toupper((unsigned char)*p);
        if (strcmp(status, "ACTIVE") && strcmp(status, "INACTIVE")) { response_error(response, "Status must be ACTIVE or INACTIVE."); return; }
        snprintf(account->status, sizeof(account->status), "%s", status);
        response_ok(response, "Customer account status changed.");
        response_line(response, "DATA|%s|%s\n", account->number, account->status);
        return;
    }

    /* ACCOUNT_CLOSE|username requires zero funds and no loan still under review. */
    if (strcmp(command, "ACCOUNT_CLOSE") == 0) {
        if (expect_count(context, 2)) return;
        if (!role_is(user, "employee")) { response_error(response, "Only employees can close customer accounts."); return; }
        if (get_username(context->fields[1], username) != 0) { response_error(response, "Customer username is invalid."); return; }
        BankUser *target = find_user(state, username);
        BankAccount *account = find_account(state, username);
        if (!target || !role_is(target, "customer") || !account) { response_error(response, "Customer account was not found."); return; }
        if (!strcmp(account->status, "CLOSED")) { response_error(response, "This account is already closed."); return; }
        if (account->balance_paise != 0) { response_error(response, "The account balance must be zero before closure."); return; }
        for (size_t i = 0; i < state->loan_count; i++) {
            BankLoan *loan = &state->loans[i];
            if (!strcmp(loan->username, username) &&
                (!strcmp(loan->status, "PENDING") || !strcmp(loan->status, "ASSIGNED"))) {
                response_error(response, "The customer has a loan application still under review."); return;
            }
        }
        /* Keep the account and history for audit; revoke access instead of deleting it. */
        snprintf(account->status, sizeof(account->status), "CLOSED");
        BankSessionRecord *customer_session = find_session(state, username);
        if (customer_session) remove_session(state, (size_t)(customer_session - state->sessions));
        response_ok(response, "Customer account closed.");
        response_line(response, "DATA|%s|%s\n", account->number, account->status);
        return;
    }

    /* FEEDBACK_LIST takes no arguments and marks the returned items reviewed. */
    if (strcmp(command, "FEEDBACK_LIST") == 0) {
        if (expect_count(context, 1)) return;
        if (!role_is(user, "manager")) { response_error(response, "Only managers can review customer feedback."); return; }
        response_ok(response, "Customer feedback.");
        size_t shown = 0;
        for (size_t i = state->feedback_count; i > 0 && shown < 40; i--) {
            BankFeedback *item = &state->feedback[i - 1];
            item->reviewed = 1;
            response_line(response, "ROW|%s|%s|%lld|%s\n", item->id, item->username, item->created_at, item->message);
            shown++;
        }
        return;
    }

    /* USER_ADD|username|password|role|name|email|phone creates any supported role. */
    if (strcmp(command, "USER_ADD") == 0) {
        if (expect_count(context, 7)) return;
        if (!role_is(user, "administrator")) { response_error(response, "Only administrators can create user accounts."); return; }
        char role[20];
        if (copy_field(role, sizeof(role), context->fields[3], 0)) { response_error(response, "User role is invalid."); return; }
        for (char *p = role; *p; p++) *p = (char)tolower((unsigned char)*p);
        char error[256];
        BankUser *created = add_user(state, context->fields[1], context->fields[2], role,
                                     context->fields[4], context->fields[5], context->fields[6],
                                     error, sizeof(error));
        if (!created) { response_error(response, error); return; }
        response_ok(response, "User account created.");
        BankAccount *created_account = find_account(state, created->username);
        response_line(response, "DATA|%s|%s|%s\n", created->username, created->role,
                      created_account ? created_account->number : "");
        return;
    }

    /* EMPLOYEE_ADD is a narrower administrator command kept for direct clients. */
    if (strcmp(command, "EMPLOYEE_ADD") == 0) {
        if (expect_count(context, 6)) return;
        if (!role_is(user, "administrator")) { response_error(response, "Only administrators can create employee accounts."); return; }
        char error[256];
        BankUser *created = add_user(state, context->fields[1], context->fields[2], "employee",
                                     context->fields[3], context->fields[4], context->fields[5], error, sizeof(error));
        if (!created) { response_error(response, error); return; }
        response_ok(response, "Employee account created.");
        response_line(response, "DATA|%s|%s\n", created->username, created->role);
        return;
    }

    /* ROLE_SET|username|role changes permissions and protects the last active admin. */
    if (strcmp(command, "ROLE_SET") == 0) {
        if (expect_count(context, 3)) return;
        if (!role_is(user, "administrator")) { response_error(response, "Only administrators can manage user roles."); return; }
        if (get_username(context->fields[1], username) != 0) { response_error(response, "Username is invalid."); return; }
        BankUser *target = find_user(state, username);
        char new_role[20];
        if (!target || copy_field(new_role, sizeof(new_role), context->fields[2], 0)) { response_error(response, "User or role was not found."); return; }
        for (char *p = new_role; *p; p++) *p = (char)tolower((unsigned char)*p);
        if (strcmp(new_role, "customer") && strcmp(new_role, "employee") && strcmp(new_role, "manager") && strcmp(new_role, "administrator")) {
            response_error(response, "Role must be customer, employee, manager, or administrator."); return;
        }
        if (role_is(target, "administrator") && strcmp(new_role, "administrator")) {
            size_t active_admins = 0;
            for (size_t i = 0; i < state->user_count; i++) if (state->users[i].active && role_is(&state->users[i], "administrator")) active_admins++;
            if (active_admins <= 1) { response_error(response, "The last active administrator cannot be demoted."); return; }
        }
        if (!strcmp(new_role, "customer") && !find_account(state, username) && add_account(state, username, 0, NULL) != 0) {
            response_error(response, "Could not create a customer account."); return;
        }
        snprintf(target->role, sizeof(target->role), "%s", new_role);
        response_ok(response, "User role changed.");
        response_line(response, "DATA|%s|%s\n", target->username, target->role);
        return;
    }

    response_error(response, "Unknown banking command.");
}

static int authenticated_operation(BankState *state, void *argument) {
    /*
     * Authentication gate for every non-LOGIN command. The in-memory session is
     * only a hint: this function compares its token with the record reloaded
     * under lock, checks expiry/account status, and refreshes last_seen before
     * dispatching a command. LOGOUT removes both copies of the session.
     */
    RequestContext *context = argument;
    BankResponse *response = context->response;
    BankSession *session = context->session;
    if (!session->authenticated) { response_error(response, "Sign in before using a banking service."); return 0; }
    /* Another connection or account action may have removed this session. */
    BankSessionRecord *record = find_session(state, session->username);
    if (!record || strcmp(record->token, session->token)) {
        session->authenticated = 0;
        session->username[0] = '\0';
        session->token[0] = '\0';
        response_error(response, "Your session expired. Please sign in again.");
        return 0;
    }
    long long now = (long long)time(NULL);
    /* Expire idle users even if their worker process is still alive. */
    if (now - record->last_seen > SESSION_LIFETIME) {
        size_t index = (size_t)(record - state->sessions);
        remove_session(state, index);
        session->authenticated = 0;
        session->username[0] = '\0';
        session->token[0] = '\0';
        response_error(response, "Your session expired. Please sign in again.");
        return 1;
    }
    BankUser *user = find_user(state, session->username);
    if (!user || !user->active) { response_error(response, "This user is inactive."); return 0; }
    if (role_is(user, "customer")) {
        BankAccount *account = find_account(state, user->username);
        if (!account || strcmp(account->status, "ACTIVE")) { response_error(response, "This account is inactive. Contact a bank manager."); return 0; }
    }
    record->last_seen = now;
    /* LOGOUT is handled here because it changes session state, not bank data. */
    if (!strcmp(context->fields[0], "LOGOUT")) {
        size_t index = (size_t)(record - state->sessions);
        remove_session(state, index);
        session->authenticated = 0;
        session->username[0] = '\0';
        session->token[0] = '\0';
        if (expect_count(context, 1)) return 1;
        response_ok(response, "Signed out.");
        return 1;
    }
    dispatch_command(state, context, user);
    return 1; /* Updating the session lease is part of every authenticated operation. */
}

void bank_execute(BankStore *store, BankSession *session, const char *request, BankResponse *response) {
    /*
     * Public command entry point used by the socket thread. It strips line
     * endings, splits the pipe-delimited request, constructs a temporary context,
     * then chooses the LOGIN path or the authenticated-command path. The copy
     * is freed before returning; response contains all bytes the caller sends.
     */
    response->length = 0;
    response->data[0] = '\0';
    if (!request || strlen(request) >= BANK_REQUEST_MAX) {
        response_error(response, "Request is missing or too large.");
        return;
    }
    char *copy = strdup(request);
    if (!copy) { response_error(response, "Server memory is unavailable."); return; }
    size_t length = strlen(copy);
    /* The network layer reads one line, but remove CR too for CRLF clients. */
    while (length && (copy[length - 1] == '\n' || copy[length - 1] == '\r')) copy[--length] = '\0';
    char *fields[12];
    int count = split_fields(copy, fields, 12);
    if (count <= 0) {
        free(copy);
        response_error(response, "Request has too many fields.");
        return;
    }
    /* The pointers in fields refer into copy and are valid through this call only. */
    RequestContext context = { .fields = fields, .count = (size_t)count, .session = session, .response = response };
    if (!strcmp(fields[0], "LOGIN")) run_locked(store, login_operation, &context, response);
    else run_locked(store, authenticated_operation, &context, response);
    free(copy);
    if (response->length >= 4 && !memcmp(response->data + response->length - 4, "END\n", 4)) return;
    clean_response(response);
}

typedef struct {
    BankSession *session;
    BankResponse *response;
} CloseSessionContext;

static int close_session_operation(BankState *state, void *argument) {
    /*
     * Disconnect cleanup runs under the same database lock as login/logout.
     * Matching the token matters: an old socket must never remove a newer login.
     */
    CloseSessionContext *context = argument;
    BankSession *session = context->session;
    if (session->authenticated) {
        BankSessionRecord *record = find_session(state, session->username);
        if (record && !strcmp(record->token, session->token)) {
            size_t index = (size_t)(record - state->sessions);
            remove_session(state, index);
            return 1;
        }
    }
    return 0;
}

void bank_close_session(BankStore *store, BankSession *session) {
    /*
     * Called by the server thread after EOF, send failure, or normal exit. Remove
     * the saved row if this connection still owns it, then clear local credentials.
     */
    if (!session || !session->authenticated) return;
    BankResponse ignored = {0};
    CloseSessionContext context = { .session = session, .response = &ignored };
    run_locked(store, close_session_operation, &context, &ignored);
    session->authenticated = 0;
    session->username[0] = '\0';
    session->token[0] = '\0';
}
