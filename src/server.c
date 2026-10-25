#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "bank.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * The parent supervises a bounded pool of worker processes. Each worker accepts
 * connections on the inherited listener and dedicates a detached pthread to
 * each connection. All workers share the store paths and semaphore handle.
 */
#define DEFAULT_PORT 5050
#define DEFAULT_WORKERS 4
#define LISTEN_BACKLOG 128

typedef struct {
    int socket_fd;  /* Connected socket that this client thread will read/write. */
    BankStore *store; /* Shared paths/semaphore; no per-client database copy is kept. */
} ClientConnection;

static volatile sig_atomic_t stopping = 0;
static pid_t worker_pids[32]; /* Child IDs used to reap or stop every worker. */
static size_t worker_count = 0; /* Valid prefix length in worker_pids. */

/* Signal handlers only request shutdown; cleanup is performed in main(). */
static void handle_parent_signal(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static int send_all(int fd, const char *buffer, size_t length) {
    /*
     * Write the entire response frame to the TCP socket. send() may return a
     * short count; MSG_NOSIGNAL prevents a disconnected client from killing a
     * worker with SIGPIPE. Return 0 on success and -1 on a closed/error socket.
     */
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(fd, buffer + sent, length - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        sent += (size_t)count;
    }
    return 0;
}

static ssize_t receive_line(int fd, char *buffer, size_t capacity) {
    /* Return bytes read, 0 on clean EOF, -1 on socket failure, or -2 if overlong. */
    size_t used = 0;
    while (used + 1 < capacity) {
        char ch;
        ssize_t count = recv(fd, &ch, 1, 0);
        if (count == 0) return used ? (ssize_t)used : 0;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buffer[used++] = ch;
        if (ch == '\n') break;
    }
    buffer[used] = '\0';
    if (used + 1 >= capacity && buffer[used - 1] != '\n') return -2;
    return (ssize_t)used;
}

static void *client_thread(void *argument) {
    /*
     * Thread entry point. The worker allocated ClientConnection before calling
     * pthread_create(); this thread copies its values and frees that allocation.
     * It then handles many sequential requests on one socket until EOF/error.
     */
    ClientConnection *connection = argument;
    int fd = connection->socket_fd;
    BankStore *store = connection->store;
    free(connection);
    /* Authentication starts empty and is established only by a successful LOGIN. */
    BankSession session = {0};
    char request[BANK_REQUEST_MAX];
    for (;;) {
        /* Request framing is one line at a time; each line gets one response frame. */
        ssize_t count = receive_line(fd, request, sizeof(request));
        if (count == -2) {
            static const char too_large[] = "ERROR|Request is too large.\nEND\n";
            send_all(fd, too_large, sizeof(too_large) - 1);
            break;
        }
        if (count <= 0) break;
        BankResponse response = {0};
        bank_execute(store, &session, request, &response);
        if (!response.length || send_all(fd, response.data, response.length) != 0) break;
    }
    /* Also clean up on abrupt disconnect, not just an explicit LOGOUT command. */
    bank_close_session(store, &session);
    close(fd);
    return NULL;
}

static void worker_loop(int listener_fd, BankStore *store) {
    /*
     * Worker process loop. All workers inherit listener_fd from the parent and
     * call accept() on it; the kernel wakes one worker for each new connection.
     * A successful accept creates a distinct socket for a detached client thread.
     */
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_size = sizeof(peer);
        int client_fd = accept(listener_fd, (struct sockaddr *)&peer, &peer_size);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EBADF || errno == EINVAL) return;
            perror("accept");
            continue;
        }
        int enabled = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        /* Heap allocation gives the detached thread its own stable argument. */
        ClientConnection *connection = malloc(sizeof(*connection));
        if (!connection) { close(client_fd); continue; }
        connection->socket_fd = client_fd;
        connection->store = store;
        pthread_t thread;
        int error = pthread_create(&thread, NULL, client_thread, connection);
        if (error != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(error));
            free(connection);
            close(client_fd);
            continue;
        }
        pthread_detach(thread);
    }
}

static int start_worker(int listener_fd, BankStore *store, pid_t *pid_out) {
    /*
     * fork() duplicates the server process. The child serves clients; the parent
     * records the child's PID for supervision. Return -1 only when fork fails.
     */
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* The child never returns to the supervisor's control loop. */
        worker_loop(listener_fd, store);
        _exit(0);
    }
    *pid_out = pid;
    return 0;
}

static int parse_positive(const char *text, long minimum, long maximum, long *value) {
    /* Parse a whole decimal argument and reject empty, trailing, or out-of-range text. */
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno || !end || *end || parsed < minimum || parsed > maximum) return -1;
    *value = parsed;
    return 0;
}

int main(int argc, char **argv) {
    /* Optional arguments select port, worker count, and data directory. */
    long port = DEFAULT_PORT, workers = DEFAULT_WORKERS;
    const char *data_dir = "./data";
    if (argc > 1 && parse_positive(argv[1], 1, 65535, &port) != 0) {
        fprintf(stderr, "Usage: %s [port [workers [data-directory]]]\n", argv[0]);
        return 2;
    }
    if (argc > 2 && parse_positive(argv[2], 1, 32, &workers) != 0) {
        fprintf(stderr, "Worker count must be from 1 to 32.\n");
        return 2;
    }
    if (argc > 3) data_dir = argv[3];
    if (argc > 4) {
        fprintf(stderr, "Usage: %s [port [workers [data-directory]]]\n", argv[0]);
        return 2;
    }

    /*
     * Startup order matters: create synchronization and storage before workers
     * fork, then create one listener that every worker can accept from.
     */
    char semaphore_name[64];
    snprintf(semaphore_name, sizeof(semaphore_name), "/banking_%ld_%ld", (long)getuid(), (long)getpid());
    /* Create one semaphore before fork so all workers serialize the same state. */
    sem_t *database_semaphore = sem_open(semaphore_name, O_CREAT | O_EXCL, 0600, 1);
    if (database_semaphore == SEM_FAILED) { perror("sem_open"); return 1; }
    /* Unlink the name now: inherited handles remain valid, but no stale name remains. */
    sem_unlink(semaphore_name);

    /* Seed the demo records only when bank.db is absent; otherwise validate it. */
    BankStore store;
    if (bank_store_init(&store, data_dir, database_semaphore) != 0) {
        fprintf(stderr, "Could not initialize the banking database in %s.\n", data_dir);
        sem_close(database_semaphore);
        return 1;
    }

    /* A TCP listening socket is the shared entry point for all client processes. */
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) { perror("socket"); sem_close(database_semaphore); return 1; }
    int enabled = 1;
    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    /* Bind locally because this is a terminal-based educational banking demo. */
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener_fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener_fd, LISTEN_BACKLOG) != 0) {
        perror("bind/listen"); close(listener_fd); sem_close(database_semaphore); return 1;
    }

    /* Install parent-only handlers so Ctrl+C/TERM can lead to orderly cleanup. */
    struct sigaction action = {0};
    action.sa_handler = handle_parent_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Start the requested pool; if fork fails, shut down the partial pool. */
    worker_count = (size_t)workers;
    for (size_t i = 0; i < worker_count; i++) {
        if (start_worker(listener_fd, &store, &worker_pids[i]) != 0) {
            perror("fork"); stopping = 1; worker_count = i; break;
        }
    }
    printf("Banking server listening on 127.0.0.1:%ld with %zu worker processes.\n", port, worker_count);
    printf("Data directory: %s\n", store.data_dir);
    printf("Demo sign-ins: admin/admin123, manager/manager123, employee/employee123, alice/alice123\n");
    fflush(stdout);

    /* Reap failed workers and replace them to keep the configured pool size. */
    while (!stopping) {
        int status = 0; /* waitpid writes the child's exit status; this demo logs PID only. */
        pid_t exited = waitpid(-1, &status, 0);
        if (exited < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            perror("waitpid");
            stopping = 1;
            break;
        }
        if (stopping) break;
        fprintf(stderr, "Worker %ld exited; starting a replacement.\n", (long)exited);
        for (size_t i = 0; i < worker_count; i++) {
            if (worker_pids[i] == exited) {
                if (start_worker(listener_fd, &store, &worker_pids[i]) != 0) {
                    perror("fork replacement");
                    stopping = 1;
                }
                break;
            }
        }
    }

    /* Stop and reap every worker before releasing shared listener/semaphore state. */
    stopping = 1;
    /* Ask workers to stop accepting clients, then wait until each child is reaped. */
    for (size_t i = 0; i < worker_count; i++) if (worker_pids[i] > 0) kill(worker_pids[i], SIGTERM);
    for (size_t i = 0; i < worker_count; i++) if (worker_pids[i] > 0) while (waitpid(worker_pids[i], NULL, 0) < 0 && errno == EINTR) {}
    close(listener_fd);
    sem_close(database_semaphore);
    puts("Banking server stopped.");
    return 0;
}
