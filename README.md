# Banking Management System

A C and POSIX implementation of the CS-513 System Software mini project. The terminal client connects to a concurrent TCP server. The server uses a process pool, pthreads, a process-shared POSIX semaphore, `flock`, and an atomically replaced file database.

New to the code? Start with the step-by-step [Learning Guide](LEARNING_GUIDE.md), which traces login, a transfer, the loan workflow, and database synchronization end to end.

## Build and run in WSL

Open Ubuntu or another Linux distribution in WSL. Install the compiler and OpenSSL development headers once:

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

Copy the extracted project into WSL's Linux filesystem so POSIX locking and file operations use the Linux filesystem. Replace the example source path with the Windows location where you extracted the project:

```bash
cp -a /mnt/c/path/to/BankingManagementSystem ~/banking-management-system
cd ~/banking-management-system
```

Compile the server and client:

```bash
make
```

Start the server in the first WSL terminal:

```bash
./build/bank_server 5050 4 ./data
```

Start a client in a second WSL terminal:

```bash
cd ~/banking-management-system
./build/bank_client 127.0.0.1 5050
```

To connect more clients, run the client command in additional terminals. In a role menu, **Sign out** returns to the login prompt and **Exit** closes the client. Stop the server with `Ctrl+C`. The `data/bank.db` file persists between runs.

## Try a complete loan workflow

1. Sign in as `alice` in a client terminal, choose **5. Apply for a loan**, and note the loan ID shown.
2. Open another client as `manager`. Choose **1. View unassigned loan applications**, then **2. Assign a loan to an employee**. Enter the loan ID and `employee`.
3. Open another client as `employee`. Choose **4. View assigned loan applications**, then **5. Approve or reject a loan**. Enter the loan ID and `approve`.
4. Sign in as `alice` again and choose **1. View account balance** or **8. Transaction history**. The approved amount appears as a `LOAN_DISBURSEMENT` entry.

## Check account creation and concurrency in WSL

Use the administrator's **1. Create user account** option to create customer, employee, manager, and administrator users directly. Employees can also create customers from **1. Open customer account**. The administrator's **3. Manage user role** option can change an existing user's role.

For a concurrency check, create two customers and a recipient, fund the two sender accounts, and log each sender in from a separate client terminal. Initiate transfers from both terminals to the same recipient close together, then sign in as the recipient and confirm its balance includes both transfers and its history shows both entries. This exercises competing updates to the shared database. To check the one-session rule, leave one client signed in and try signing in as that same user from another terminal; the second login should be rejected.

For account closure, try closing a customer with a nonzero balance and confirm it is refused. Transfer or withdraw the remaining funds, ensure no loan is pending or assigned, then close the account as an employee. The account should remain `CLOSED` and a manager should not be able to reactivate it.

## Demo sign-ins

| Role | Username | Password |
| --- | --- | --- |
| Administrator | `admin` | `admin123` |
| Manager | `manager` | `manager123` |
| Employee | `employee` | `employee123` |
| Customer | `alice` | `alice123` |

These demo accounts are created only when `data/bank.db` does not exist. Alice starts with Rs 25,000.00 and an opening balance entry. Change demo passwords from each role's menu before using a shared demonstration environment.

To reset the database, stop the server and remove its data directory:

```bash
rm -rf data
```

The next server start recreates the demo accounts.

## How the implementation fits together

1. `src/bank.h` defines the records and fixed limits shared by the client and server.
2. `src/server.c` opens the TCP listener, forks worker processes, and gives each connection its own pthread.
3. `src/client.c` displays the menus and sends one line-based command for each action.
4. `src/store.c` validates the signed-in user's role, applies banking rules, and serializes access with a semaphore and `flock`.
5. A successful change writes a complete temporary database snapshot, calls `fsync()`, and atomically renames it into place. Transfers update both accounts and both passbooks in the same saved snapshot.

To add a banking operation, add its menu and request in `src/client.c`, handle the command and check its role in `dispatch_command()` in `src/store.c`, and document the command and persistence behavior in `DESIGN.md`. Build again with `make`.

## Implemented features

- **Customer:** view balance, deposit, withdraw, transfer to another active customer, apply for a loan, change password, submit feedback, and view transaction history.
- **Employee:** open customer accounts, update customer contact details, close empty customer accounts, view assigned loan applications, approve or reject assigned applications, and view customer passbooks. Closure requires a zero balance and no loan application under review.
- **Manager:** view unassigned loan applications, assign applications to active employees, activate or deactivate customer accounts, and review feedback.
- **Administrator:** create customer, employee, manager, or administrator accounts; modify customer or employee details; and manage user roles. Employees can also open customer accounts.
- Server-side role checks protect every operation; menus do not grant permissions by themselves.

## Implementation map

| File | Responsibility |
| --- | --- |
| `src/server.c` | TCP listener, `fork()` worker pool, `waitpid()` supervision, and a pthread per client connection. |
| `src/client.c` | Interactive role menus, socket client, password prompts, and terminal input. |
| `src/store.c` | Authentication, role checks, banking rules, locking, transaction history, and persistence. |
| `src/bank.h` | Shared data structures and storage interface. |
| `Makefile` | Builds `build/bank_server` and `build/bank_client`. |
| `DESIGN.md` | Architecture, class diagram, storage schema, concurrency sequence, and requirement mapping. |

## Concurrency and ACID behavior

The server parent creates worker processes with `fork()`. Each worker accepts TCP connections and starts a detached pthread for each client. A named POSIX semaphore serializes database access across threads and worker processes. The same critical section also locks the stable `data/bank.lock` file with `flock()`.

Each operation reads the latest complete state, checks permissions and business rules, updates the in-memory state, then writes a temporary database file with `write()`. The server calls `fsync()`, renames the complete file over `bank.db`, and syncs the data directory. A transfer's sender debit, recipient credit, and both passbook entries are committed together. Deposits, withdrawals, loan decisions, and session creation use the same lock-and-commit path.

Passwords are salted PBKDF2-HMAC-SHA256 hashes using OpenSSL. Money is stored as integer paise. A stored session token enforces one active session per username across all workers; logout and connection close remove the session.

## Scope

This is an educational, local banking simulation with a single file-backed database. It does not connect to real banking services. Approving a loan immediately credits the customer's account and records a `LOAN_DISBURSEMENT` transaction.
