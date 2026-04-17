# Project-2-IT355

## Charles's CWE modules

- **CWE-89 (SQL Injection)** — [UserDatabase.java](UserDatabase.java): all queries use `PreparedStatement` with `?` placeholders.
- **CWE-312 (Cleartext Storage)** — [EncryptionService.java](EncryptionService.java), [UserDatabase.java](UserDatabase.java): account balance is AES-GCM encrypted before persisting.
- **CWE-384 (Session Fixation)** — [SessionManager.java](SessionManager.java): fresh `SecureRandom` session ID minted on every login; old sessions invalidated.
- **CWE-613 (Insufficient Session Expiration)** — [SessionManager.java](SessionManager.java): idle timeout (15 min) + absolute timeout (1 hr).
- **CWE-778 (Insufficient Logging)** — [SecurityLogger.java](SecurityLogger.java): append-only `security.log` of auth, session, and suspicious events.

## Running the demo

Requires **Java 11+** and the `sqlite-jdbc` driver.

1. Download `sqlite-jdbc-3.47.1.0.jar` (or any recent 3.x build) from Maven Central:
   https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/
2. Put it in the project root.
3. Compile and run:

```sh
javac -cp sqlite-jdbc-3.47.1.0.jar *.java
java  -cp .:sqlite-jdbc-3.47.1.0.jar Main
```

On first run a demo user `alice` / `hunter2` is seeded with 100 credits.
Spin the reels, then inspect `security.log` to see the audit trail.

### Files created at runtime
- `slotmachine.db` — SQLite database (users, spin_history)
- `.slotmachine.key` — AES-256 key for balance encryption (owner-only)
- `security.log` — append-only security event log

These are gitignored in practice; do not commit them.
