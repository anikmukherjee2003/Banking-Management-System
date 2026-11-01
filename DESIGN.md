# Project Blueprint

## Process architecture

```mermaid
flowchart LR
    C1[Terminal client 1] -->|TCP text protocol| L[Listening socket]
    C2[Terminal client 2] -->|TCP text protocol| L
    L --> P[Server parent]
    P -->|fork and waitpid| W1[Worker process]
    P --> WN[Worker process N]
    W1 --> T1[Pthread per client]
    WN --> TN[Pthread per client]
    T1 --> S[Banking service and role checks]
    TN --> S
    S -->|sem_wait and sem_post| M[Process-shared critical section]
    M -->|flock| F[bank.lock]
    M -->|write fsync rename| D[(bank.db)]
```

The parent accepts no clients directly. Worker processes inherit the listening socket and accept connections concurrently. Each connection has one client thread and one authenticated session. All state changes pass through the banking service and acquire the semaphore and file lock.

## Domain class diagram

```mermaid
classDiagram
    class User {
        +username
        +saltedPasswordHash
        +role
        +active
        +name
        +email
        +phone
    }
    class Customer {
        +viewBalance()
        +deposit()
        +withdraw()
        +transfer()
        +applyForLoan()
        +submitFeedback()
    }
    class Employee {
        +openCustomer()
        +modifyCustomer()
        +closeCustomerAccount()
        +processLoan()
        +viewPassbook()
    }
    class Manager {
        +assignLoan()
        +setAccountStatus()
        +reviewFeedback()
    }
    class Administrator {
        +createUserAccount(role)
        +addEmployee()
        +modifyUser()
        +setRole()
    }
    class Account {
        +accountNumber
        +balancePaise
        +status
    }
    class Transaction {
        +transactionId
        +type
        +amountPaise
        +balanceAfterPaise
        +relatedAccount
        +reference
        +timestamp
    }
    class LoanApplication {
        +loanId
        +amountPaise
        +purpose
        +status
        +assignedEmployee
        +reviewer
    }
    class Feedback {
        +feedbackId
        +message
        +reviewed
        +timestamp
    }
    class FraudAlert {
        +alertId
        +customer
        +reason
        +details
        +holdApplied
        +reviewedBy
        +createdAt
        +reviewedAt
    }
    class Session {
        +token
        +workerPid
        +lastSeen
    }

    User <|-- Customer
    User <|-- Employee
    User <|-- Manager
    User <|-- Administrator
    Customer "1" --> "1" Account : owns
    Account "1" --> "0..*" Transaction : ledger
    Customer "1" --> "0..*" LoanApplication : submits
    Employee "0..1" --> "0..*" LoanApplication : processes
    Customer "1" --> "0..*" Feedback : writes
    Customer "1" --> "0..*" FraudAlert : triggers
    User "1" --> "0..1" Session : holds
```

The role types in this conceptual diagram are stored as role values in C user records; the implementation uses shared C structures rather than separate object subclasses.

## File database schema

`data/bank.db` is a line-oriented database. User-controlled text cannot contain the `|` field separator or control characters. Monetary values are integer paise.

| Record | Fields | Purpose |
| --- | --- | --- |
| `META` | next account, transaction, loan, feedback, and fraud alert IDs | ID generation. The loader accepts the older four-ID format too. |
| `USER` | username, salt, password hash, role, active flag, contact details | Credentials and permissions. |
| `ACCOUNT` | username, account number, balance, status (`ACTIVE`, `INACTIVE`, `CLOSED`, or `FRAUD_HOLD`) | Customer account state. A fraud hold is released through administrator alert review. |
| `TX` | ID, owner, type, amount, balance after, related account, reference, time, memo | Passbook and audit trail. |
| `LOAN` | ID, applicant, amount, purpose, status, assignee, reviewer, timestamps | Loan processing workflow. |
| `FEEDBACK` | ID, customer, message, reviewed flag, timestamp | Customer feedback. |
| `FRAUD` | ID, customer, reason, details, hold flag, reviewed flag, creation time, reviewer, review time | Persistent fraud alert history and account hold audit. |
| `SESSION` | username, random token, worker PID, last activity | One active login per user. |

## Transaction sequence

```mermaid
sequenceDiagram
    actor Customer
    participant Client
    participant Thread as Client pthread
    participant Store as Banking service
    participant Sync as Semaphore and flock
    participant File as bank.db
    Customer->>Client: Request a transfer
    Client->>Thread: TCP command line
    Thread->>Store: Check session and role
    Store->>Sync: Acquire semaphore and file lock
    Store->>File: Read current state
    Store->>Store: Validate accounts and available funds
    Store->>Store: Debit, credit, append both ledger entries
    Store->>File: Write temp, fsync, rename, sync directory
    Store->>Sync: Release locks
    Store-->>Thread: Transfer result
    Thread-->>Client: Response lines
```

Fraud checks run inside the same locked operation before a suspicious transfer is posted. A transfer of Rs 100,000 or more, or the third outgoing transfer within five minutes, is blocked and creates a hold alert. Three insufficient-funds transfers or withdrawals within ten minutes create a hold. The attempt and alert are saved through the regular snapshot commit path. An administrator can list alerts and resolve them; the account returns to `ACTIVE` only after all its open hold-causing alerts have been reviewed.

## Requirement mapping

| Requirement from the project brief | C implementation |
| --- | --- |
| Socket programming and multiple clients | IPv4 TCP sockets in `src/server.c`; `src/client.c` connects using `getaddrinfo()`. |
| Concurrent clients | Parent uses `fork()` for worker processes; each worker starts a pthread for each accepted client. |
| Process management | Parent reaps workers with `waitpid()` and starts a replacement if one exits. |
| File management and locking | POSIX `open`, `read`, `write`, `fsync`, `rename`, `flock`, and directory sync. |
| Semaphores and synchronization | `sem_open`, `sem_wait`, and `sem_post` serialize database operations across worker processes and threads. |
| One session per user | Session records and random tokens are stored in the database and checked on each request. |
| ACID-oriented updates | One critical section validates and changes the state; a complete replacement file is synced and atomically renamed into place. |
| Roles and modules | Customer, employee, manager, and administrator operations are enforced by server-side role checks. |
| Rule-based fraud review | Transfer amount, recent transfer velocity, and repeated insufficient-funds attempts create saved alerts and administrator-reviewed account holds. |
