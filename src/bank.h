#ifndef BANKING_MANAGEMENT_SYSTEM_BANK_H
#define BANKING_MANAGEMENT_SYSTEM_BANK_H

#include <limits.h>
#include <semaphore.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Fixed capacities keep memory use predictable and prevent a database record,
 * request, or response from growing without a limit. Counts in BankState tell
 * the code how many slots in each fixed-size array currently contain records.
 */
#define BANK_MAX_USERS 128
#define BANK_MAX_TRANSACTIONS 4096
#define BANK_MAX_LOANS 512
#define BANK_MAX_FEEDBACK 512
#define BANK_MAX_SESSIONS 128
#define BANK_REQUEST_MAX 8192
#define BANK_RESPONSE_MAX 65536

/* One login identity. Customers also have a BankAccount with the same username. */
typedef struct {
    char username[33];       /* Canonical lowercase login name, plus '\0'. */
    char salt_hex[33];       /* 16 random salt bytes encoded as 32 hex characters. */
    char password_hash[65];  /* 32 derived hash bytes encoded as 64 hex characters. */
    char role[20];           /* customer, employee, manager, or administrator. */
    int active;              /* Disabled users cannot sign in. */
    char name[101];          /* Display name; fixed-size storage includes terminator. */
    char email[161];         /* Optional contact detail. */
    char phone[41];          /* Optional contact detail. */
} BankUser;

/*
 * Customer account state. Balances use integer paise (100 paise = 1 rupee)
 * rather than floating point, avoiding rounding errors in financial math.
 */
typedef struct {
    char username[33];      /* Owner's BankUser.username. */
    char number[16];         /* Human-readable generated account number. */
    long long balance_paise; /* Current balance in the smallest supported unit. */
    char status[12];         /* ACTIVE, INACTIVE, or CLOSED. */
} BankAccount;

/*
 * Immutable-style passbook entry. A transfer writes one entry for each side;
 * both entries share reference so they can be recognized as one operation.
 */
typedef struct {
    char id[20];                    /* Unique ledger row identifier. */
    char username[33];              /* Account whose passbook contains this row. */
    char type[24];                   /* DEPOSIT, WITHDRAW, TRANSFER_OUT, etc. */
    long long amount_paise;          /* Operation amount in integer paise. */
    long long balance_after_paise;   /* Owner's balance immediately after the row. */
    char related_account[16];        /* Other account number for a transfer, if any. */
    char reference[20];              /* Shared operation or loan reference, if any. */
    long long created_at;            /* Unix timestamp in seconds. */
    char memo[241];                  /* Optional explanation shown in history. */
} BankTransaction;

/* A loan moves from PENDING to ASSIGNED, then APPROVED or REJECTED. */
typedef struct {
    char id[20];                     /* Generated loan application identifier. */
    char username[33];               /* Customer who submitted the application. */
    long long amount_paise;           /* Requested amount in integer paise. */
    char purpose[241];               /* Customer's explanation for the loan. */
    char status[16];                  /* Current workflow state. */
    char assigned_to[33];             /* Employee selected by a manager; empty if pending. */
    char reviewed_by[33];             /* Employee who made the final decision. */
    long long created_at;             /* Submission time, Unix seconds. */
    long long reviewed_at;            /* Decision time; zero until reviewed. */
} BankLoan;

/* Feedback remains in the database after review so it can be audited later. */
typedef struct {
    char id[20];          /* Generated feedback identifier. */
    char username[33];    /* Customer who submitted the message. */
    char message[1001];   /* Message text; pipe/control characters are rejected. */
    int reviewed;         /* Nonzero after a manager has viewed the feedback. */
    long long created_at; /* Submission time, Unix seconds. */
} BankFeedback;

/*
 * Session metadata lives in bank.db so separate forked workers can enforce the
 * one-session rule. The random token ties a socket thread to this exact record.
 */
typedef struct {
    char username[33];    /* At most one persisted session per username. */
    char token[65];        /* 32 random bytes as hex; never sent back to the client. */
    pid_t worker_pid;      /* Used to discard records left by a dead worker. */
    long long last_seen;   /* Refreshed by authenticated requests for expiry checks. */
} BankSessionRecord;

/*
 * Complete in-memory database snapshot. The *_count fields define the valid
 * prefix of each matching array; unused tail slots are ignored. The next_* IDs
 * are saved with the records so restarts do not reuse identifiers.
 */
typedef struct {
    int next_account;
    int next_transaction;
    int next_loan;
    int next_feedback;
    size_t user_count;
    size_t account_count;
    size_t transaction_count;
    size_t loan_count;
    size_t feedback_count;
    size_t session_count;
    BankUser users[BANK_MAX_USERS];
    BankAccount accounts[BANK_MAX_USERS];
    BankTransaction transactions[BANK_MAX_TRANSACTIONS];
    BankLoan loans[BANK_MAX_LOANS];
    BankFeedback feedback[BANK_MAX_FEEDBACK];
    BankSessionRecord sessions[BANK_MAX_SESSIONS];
} BankState;

/*
 * A server response is assembled before it is sent. length counts valid bytes
 * in data; the client reads newline-delimited rows until it receives END.
 */
typedef struct {
    char data[BANK_RESPONSE_MAX];
    size_t length;
} BankResponse;

/* Shared server configuration passed to every command handler. */
typedef struct {
    char data_dir[PATH_MAX];
    char database_path[PATH_MAX];
    char lock_path[PATH_MAX];
    sem_t *database_semaphore;
} BankStore;

/*
 * Thread-local copy of the connection's login. The database token is checked
 * on every request, so stale or replaced sessions cannot keep using the socket.
 */
typedef struct {
    int authenticated;
    char username[33];
    char token[65];
} BankSession;

/* Prepare the storage paths and create or validate the initial database. */
int bank_store_init(BankStore *store, const char *data_dir, sem_t *database_semaphore);
/* Parse one newline-delimited command, authorize it, and fill a framed response. */
void bank_execute(BankStore *store, BankSession *session, const char *request, BankResponse *response);
/* Remove the matching persisted session when a client connection ends. */
void bank_close_session(BankStore *store, BankSession *session);

#endif
