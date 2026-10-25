#define _POSIX_C_SOURCE 200809L

#include "bank.h"

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MENU_EXIT 0
#define MENU_LOGOUT 1

/*
 * This file is the interactive front end. It prompts a person, turns each
 * answer into a protocol command, sends it to the server, and prints the
 * response. The server owns the real banking state and repeats validation and
 * authorization; client menus are a convenience, not a security boundary.
 *
 * Protocol overview:
 *   request:  COMMAND|argument1|argument2\n
 *   response: OK|message or ERROR|message, followed by DATA/ROW lines and END
 * The pipe separates fields, so read_field rejects pipes and control bytes.
 */
static int read_field(const char *label, char *output, size_t capacity, int allow_empty) {
    /*
     * Ask for one ordinary (non-secret) value. output must have capacity bytes;
     * allow_empty is used for optional contact details and "keep current value"
     * prompts. Returns 0 for accepted input and -1 when stdin reaches EOF.
     */
    for (;;) {
        printf("%s", label);
        fflush(stdout);
        if (!fgets(output, (int)capacity, stdin)) return -1;
        size_t length = strlen(output);
        /* fgets keeps the newline when it fits; remove it before making a command. */
        if (length && output[length - 1] == '\n') output[--length] = '\0';
        else if (!feof(stdin)) {
            /* Discard the rest of an overlong answer so it cannot become the next prompt's input. */
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            puts("Input is too long; try again.");
            continue;
        }
        /* Accept Windows CRLF input as well as Unix LF input. */
        if (length && output[length - 1] == '\r') output[--length] = '\0';
        if (!allow_empty && length == 0) { puts("A value is required."); continue; }
        /* The server protocol uses '|' as a separator and lines as message boundaries. */
        int invalid = 0;
        for (size_t i = 0; i < length; i++) {
            unsigned char ch = (unsigned char)output[i];
            if (ch == '|' || ch < 32 || ch == 127) invalid = 1;
        }
        if (invalid) { puts("The pipe symbol and control characters are not allowed."); continue; }
        return 0;
    }
}

static int read_secret(const char *label, char *output, size_t capacity) {
    /*
     * Read a password without echoing it to the terminal. getpass returns a
     * temporary library buffer, so copy the value into the caller's bounded
     * storage before another password prompt can overwrite that buffer.
     */
    for (;;) {
        char *value = getpass(label);
        if (!value) return -1;
        size_t length = strlen(value);
        int invalid = length >= capacity;
        for (size_t i = 0; i < length; i++) {
            unsigned char ch = (unsigned char)value[i];
            if (ch == '|' || ch < 32 || ch == 127) invalid = 1;
        }
        if (invalid) { puts("Password is too long or contains a disallowed character."); continue; }
        memcpy(output, value, length + 1);
        return 0;
    }
}

static ssize_t receive_line(int fd, char *buffer, size_t capacity) {
    /*
     * Read one newline-terminated response line. TCP does not preserve send()
     * boundaries, so this loops until LF arrives. Return byte count, 0 at EOF,
     * -1 on socket error, or -2 when the destination is too small.
     */
    size_t used = 0;
    while (used + 1 < capacity) {
        char ch;
        ssize_t count = recv(fd, &ch, 1, 0);
        if (count == 0) return used ? (ssize_t)used : 0;
        if (count < 0) {
            /* A signal may interrupt recv() without ending the connection. */
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

static int send_all(int fd, const char *buffer, size_t length) {
    /*
     * Send exactly length bytes. A successful send() may accept only a prefix,
     * so sent tracks progress and the next call starts at buffer + sent.
     */
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(fd, buffer + sent, length - sent, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        sent += (size_t)count;
    }
    return 0;
}

static void display_line(char *line) {
    /*
     * The first field is a protocol tag: OK and ERROR are status messages,
     * DATA is a single result, and ROW is one item in a list. Remove line ending
     * bytes before printing so the console controls the formatting.
     */
    size_t length = strlen(line);
    while (length && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';
    if (!strncmp(line, "OK|", 3)) printf("\n%s\n", line + 3);
    else if (!strncmp(line, "ERROR|", 6)) printf("\nError: %s\n", line + 6);
    else if (!strncmp(line, "DATA|", 5)) printf("  %s\n", line + 5);
    else if (!strncmp(line, "ROW|", 4)) printf("  - %s\n", line + 4);
}

static int send_request(int fd, char *first_line, size_t first_capacity, const char *format, ...) {
    /*
     * Build one command from a printf-style format, append its newline, and
     * send it. Then read and display every response line through the END marker.
     * first_line is optional output storage: LOGIN uses it to learn the role
     * returned by the server; ordinary commands pass NULL. Returns -1 if the
     * command cannot be sent or a complete response cannot be read.
     */
    char request[BANK_REQUEST_MAX];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(request, sizeof(request) - 2, format, arguments);
    va_end(arguments);
    if (length < 0 || length >= (int)sizeof(request) - 2) {
        puts("Request is too long.");
        return -1;
    }
    /* Newline ends the request on the server; NUL is local string termination. */
    request[length++] = '\n';
    request[length] = '\0';
    if (send_all(fd, request, (size_t)length) != 0) return -1;
    if (first_line && first_capacity) first_line[0] = '\0';
    int got_first = 0;
    char line[4096];
    for (;;) {
        ssize_t count = receive_line(fd, line, sizeof(line));
        if (count <= 0) return -1;
        /* END is the frame boundary; without it the next request could misread rows. */
        if (!strcmp(line, "END\n") || !strcmp(line, "END\r\n")) break;
        if (!got_first && first_line && first_capacity) {
            size_t copy = (size_t)count < first_capacity - 1 ? (size_t)count : first_capacity - 1;
            memcpy(first_line, line, copy);
            first_line[copy] = '\0';
            got_first = 1;
        }
        display_line(line);
    }
    return 0;
}

static int connect_server(const char *host, const char *port) {
    /*
     * Convert a host/port pair into candidate addresses, then try each one.
     * On success the caller owns the connected descriptor and must close it.
     */
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(host, port, &hints, &addresses);
    if (status != 0) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status)); return -1; }
    int fd = -1;
    /* A hostname may resolve to several families/addresses; try until one works. */
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    return fd;
}

static void change_password(int fd) {
    /* Compare confirmation locally; the completed request path clears stack copies. */
    char current[129], next[129], confirmation[129];
    if (read_secret("Current password: ", current, sizeof(current)) ||
        read_secret("New password (at least 8 characters): ", next, sizeof(next)) ||
        read_secret("Confirm new password: ", confirmation, sizeof(confirmation))) return;
    if (strcmp(next, confirmation)) { puts("Passwords do not match."); return; }
    send_request(fd, NULL, 0, "CHANGE_PASSWORD|%s|%s", current, next);
    memset(current, 0, sizeof(current));
    memset(next, 0, sizeof(next));
    memset(confirmation, 0, sizeof(confirmation));
}

static int customer_menu(int fd) {
    /*
     * Customer menu. Each branch gathers the arguments for one command and
     * delegates the actual decision to the server. MENU_LOGOUT returns to the
     * login prompt on this connection; MENU_EXIT ends the client program.
     * Choice map: 1 BALANCE, 2 DEPOSIT, 3 WITHDRAW, 4 TRANSFER,
     * 5 LOAN_APPLY, 6 CHANGE_PASSWORD, 7 FEEDBACK_ADD, 8 HISTORY.
     */
    char choice[32], recipient[64], amount[64], purpose[256], message[1024];
    for (;;) {
        puts("\nCUSTOMER MENU\n1. View account balance\n2. Deposit money\n3. Withdraw money\n4. Transfer funds\n5. Apply for a loan\n6. Change password\n7. Submit feedback\n8. Transaction history\n9. Sign out\n0. Exit");
        if (read_field("Choose: ", choice, sizeof(choice), 0)) return MENU_EXIT;
        if (!strcmp(choice, "1")) send_request(fd, NULL, 0, "BALANCE");
        else if (!strcmp(choice, "2")) {
            if (!read_field("Deposit amount in rupees: ", amount, sizeof(amount), 0)) send_request(fd, NULL, 0, "DEPOSIT|%s", amount);
        } else if (!strcmp(choice, "3")) {
            if (!read_field("Withdrawal amount in rupees: ", amount, sizeof(amount), 0)) send_request(fd, NULL, 0, "WITHDRAW|%s", amount);
        } else if (!strcmp(choice, "4")) {
            if (!read_field("Recipient username: ", recipient, sizeof(recipient), 0) &&
                !read_field("Transfer amount in rupees: ", amount, sizeof(amount), 0))
                send_request(fd, NULL, 0, "TRANSFER|%s|%s", recipient, amount);
        } else if (!strcmp(choice, "5")) {
            if (!read_field("Loan amount in rupees: ", amount, sizeof(amount), 0) &&
                !read_field("Purpose: ", purpose, sizeof(purpose), 0))
                send_request(fd, NULL, 0, "LOAN_APPLY|%s|%s", amount, purpose);
        } else if (!strcmp(choice, "6")) change_password(fd);
        else if (!strcmp(choice, "7")) {
            if (!read_field("Feedback: ", message, sizeof(message), 0)) send_request(fd, NULL, 0, "FEEDBACK_ADD|%s", message);
        } else if (!strcmp(choice, "8")) send_request(fd, NULL, 0, "HISTORY");
        else if (!strcmp(choice, "9")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_LOGOUT; }
        else if (!strcmp(choice, "0")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_EXIT; }
        else puts("Choose one of the displayed options.");
    }
}

static int employee_menu(int fd) {
    /*
     * Employee menu. The server limits customer edits and loan decisions to
     * authorized records; these prompts only collect usernames, loan IDs, etc.
     * Choice map: 1 CUSTOMER_ADD, 2 USER_MODIFY, 3 ACCOUNT_CLOSE,
     * 4 LOANS_ASSIGNED, 5 LOAN_DECIDE, 6 HISTORY for the selected customer.
     */
    char choice[32], username[64], password[129], name[128], email[180], phone[80], loan_id[32], decision[32];
    for (;;) {
        puts("\nEMPLOYEE MENU\n1. Open customer account\n2. Modify customer details\n3. Close customer account\n4. View assigned loan applications\n5. Approve or reject a loan\n6. View customer passbook\n7. Change password\n8. Sign out\n0. Exit");
        if (read_field("Choose: ", choice, sizeof(choice), 0)) return MENU_EXIT;
        if (!strcmp(choice, "1")) {
            if (read_field("New username: ", username, sizeof(username), 0) ||
                read_secret("Temporary password: ", password, sizeof(password)) ||
                read_field("Full name: ", name, sizeof(name), 0) ||
                read_field("Email (optional): ", email, sizeof(email), 1) ||
                read_field("Phone (optional): ", phone, sizeof(phone), 1)) continue;
            send_request(fd, NULL, 0, "CUSTOMER_ADD|%s|%s|%s|%s|%s", username, password, name, email, phone);
            memset(password, 0, sizeof(password));
        } else if (!strcmp(choice, "2")) {
            if (read_field("Customer username: ", username, sizeof(username), 0) ||
                read_field("New name (blank to keep): ", name, sizeof(name), 1) ||
                read_field("New email (blank to keep): ", email, sizeof(email), 1) ||
                read_field("New phone (blank to keep): ", phone, sizeof(phone), 1)) continue;
            send_request(fd, NULL, 0, "USER_MODIFY|%s|%s|%s|%s", username, name, email, phone);
        } else if (!strcmp(choice, "3")) {
            if (!read_field("Customer username to close: ", username, sizeof(username), 0))
                send_request(fd, NULL, 0, "ACCOUNT_CLOSE|%s", username);
        } else if (!strcmp(choice, "4")) send_request(fd, NULL, 0, "LOANS_ASSIGNED");
        else if (!strcmp(choice, "5")) {
            if (!read_field("Loan ID: ", loan_id, sizeof(loan_id), 0) &&
                !read_field("Decision (approve/reject): ", decision, sizeof(decision), 0))
                send_request(fd, NULL, 0, "LOAN_DECIDE|%s|%s", loan_id, decision);
        } else if (!strcmp(choice, "6")) {
            if (!read_field("Customer username: ", username, sizeof(username), 0)) send_request(fd, NULL, 0, "HISTORY|%s", username);
        } else if (!strcmp(choice, "7")) change_password(fd);
        else if (!strcmp(choice, "8")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_LOGOUT; }
        else if (!strcmp(choice, "0")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_EXIT; }
        else puts("Choose one of the displayed options.");
    }
}

static int manager_menu(int fd) {
    /*
     * Manager menu for account activation, assigning loans, and feedback review.
     * Choice map: 1 LOANS_UNASSIGNED, 2 LOAN_ASSIGN, 3 ACCOUNT_STATUS,
     * 4 FEEDBACK_LIST.
     */
    char choice[32], username[64], loan_id[32], employee[64], status[32];
    for (;;) {
        puts("\nMANAGER MENU\n1. View unassigned loan applications\n2. Assign a loan to an employee\n3. Activate or deactivate customer account\n4. Review customer feedback\n5. Change password\n6. Sign out\n0. Exit");
        if (read_field("Choose: ", choice, sizeof(choice), 0)) return MENU_EXIT;
        if (!strcmp(choice, "1")) send_request(fd, NULL, 0, "LOANS_UNASSIGNED");
        else if (!strcmp(choice, "2")) {
            if (!read_field("Loan ID: ", loan_id, sizeof(loan_id), 0) &&
                !read_field("Employee username: ", employee, sizeof(employee), 0))
                send_request(fd, NULL, 0, "LOAN_ASSIGN|%s|%s", loan_id, employee);
        } else if (!strcmp(choice, "3")) {
            if (!read_field("Customer username: ", username, sizeof(username), 0) &&
                !read_field("Status (active/inactive): ", status, sizeof(status), 0))
                send_request(fd, NULL, 0, "ACCOUNT_STATUS|%s|%s", username, status);
        } else if (!strcmp(choice, "4")) send_request(fd, NULL, 0, "FEEDBACK_LIST");
        else if (!strcmp(choice, "5")) change_password(fd);
        else if (!strcmp(choice, "6")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_LOGOUT; }
        else if (!strcmp(choice, "0")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_EXIT; }
        else puts("Choose one of the displayed options.");
    }
}

static int administrator_menu(int fd) {
    /*
     * Administrator menu. Creating an employee means choosing employee as the
     * role in USER_ADD; role and detail permissions are checked again server-side.
     * Choice map: 1 USER_ADD, 2 USER_MODIFY, 3 ROLE_SET.
     */
    char choice[32], username[64], password[129], name[128], email[180], phone[80], role[32];
    for (;;) {
        puts("\nADMINISTRATOR MENU\n1. Create user account\n2. Modify customer or employee details\n3. Manage user role\n4. Change password\n5. Sign out\n0. Exit");
        if (read_field("Choose: ", choice, sizeof(choice), 0)) return MENU_EXIT;
        if (!strcmp(choice, "1")) {
            if (read_field("Role (customer/employee/manager/administrator): ", role, sizeof(role), 0) ||
                read_field("New username: ", username, sizeof(username), 0) ||
                read_secret("Temporary password: ", password, sizeof(password)) ||
                read_field("Full name: ", name, sizeof(name), 0) ||
                read_field("Email (optional): ", email, sizeof(email), 1) ||
                read_field("Phone (optional): ", phone, sizeof(phone), 1)) continue;
            send_request(fd, NULL, 0, "USER_ADD|%s|%s|%s|%s|%s|%s", username, password, role, name, email, phone);
            memset(password, 0, sizeof(password));
        } else if (!strcmp(choice, "2")) {
            if (read_field("Username: ", username, sizeof(username), 0) ||
                read_field("New name (blank to keep): ", name, sizeof(name), 1) ||
                read_field("New email (blank to keep): ", email, sizeof(email), 1) ||
                read_field("New phone (blank to keep): ", phone, sizeof(phone), 1)) continue;
            send_request(fd, NULL, 0, "USER_MODIFY|%s|%s|%s|%s", username, name, email, phone);
        } else if (!strcmp(choice, "3")) {
            if (!read_field("Username: ", username, sizeof(username), 0) &&
                !read_field("Role (customer/employee/manager/administrator): ", role, sizeof(role), 0))
                send_request(fd, NULL, 0, "ROLE_SET|%s|%s", username, role);
        } else if (!strcmp(choice, "4")) change_password(fd);
        else if (!strcmp(choice, "5")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_LOGOUT; }
        else if (!strcmp(choice, "0")) { send_request(fd, NULL, 0, "LOGOUT"); return MENU_EXIT; }
        else puts("Choose one of the displayed options.");
    }
}

int main(int argc, char **argv) {
    /*
     * Program entry point: parse optional host/port, connect once, then keep the
     * socket open for sign-in and the selected menu. Closing the socket also lets
     * the server release the persisted session if the user exits unexpectedly.
     */
    signal(SIGPIPE, SIG_IGN);
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const char *port = argc > 2 ? argv[2] : "5050";
    if (argc > 3) { fprintf(stderr, "Usage: %s [host [port]]\n", argv[0]); return 2; }
    int fd = connect_server(host, port);
    if (fd < 0) { fprintf(stderr, "Could not connect to the bank server at %s:%s.\n", host, port); return 1; }
    printf("Connected to the Banking Management System at %s:%s.\n", host, port);
    int exit_client = 0;
    /* After an explicit sign-out, signed_in is true and this loop asks to log in again. */
    while (!exit_client) {
        int signed_in = 0;
        /* Limit failed sign-in attempts before closing this client session. */
        for (int attempt = 0; attempt < 3; attempt++) {
            char username[64], password[129], first[256], role[32], name[128];
            if (read_field("Username: ", username, sizeof(username), 0) ||
                read_secret("Password: ", password, sizeof(password))) {
                exit_client = 1;
                break;
            }
            if (send_request(fd, first, sizeof(first), "LOGIN|%s|%s", username, password) != 0) {
                fprintf(stderr, "The server connection closed.\n");
                memset(password, 0, sizeof(password));
                close(fd);
                return 1;
            }
            memset(password, 0, sizeof(password));
            /* The server, rather than the menu, determines the authorized role. */
            /* Successful LOGIN returns role and display name in its first OK line. */
            if (sscanf(first, "OK|%31[^|]|%127[^\r\n]", role, name) == 2) {
                int menu_result = MENU_EXIT;
                if (!strcmp(role, "customer")) menu_result = customer_menu(fd);
                else if (!strcmp(role, "employee")) menu_result = employee_menu(fd);
                else if (!strcmp(role, "manager")) menu_result = manager_menu(fd);
                else if (!strcmp(role, "administrator")) menu_result = administrator_menu(fd);
                signed_in = 1;
                if (menu_result == MENU_EXIT) exit_client = 1;
                break;
            }
        }
        if (!signed_in) exit_client = 1;
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return 0;
}
