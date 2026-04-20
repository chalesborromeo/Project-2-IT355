# Project-2-IT355


## Running the demo

Requires **Java 11+** and the `sqlite-jdbc` driver (already vendored in `lib/`).

**VSCode (Red Hat Java extension):** just run `Main.java` — `.vscode/settings.json` adds `lib/**/*.jar` to the classpath automatically.

**Command line:**

```sh
javac -cp "lib/sqlite-jdbc-3.47.1.0.jar" *.java
java  -cp ".:lib/sqlite-jdbc-3.47.1.0.jar" Main
```

On first run a demo user `alice` / `hunter2` is seeded with 100 credits.
Spin the reels, then inspect `security.log` to see the audit trail.

### Files created at runtime
- `slotmachine.db` — SQLite database (users, spin_history)
- `.slotmachine.key` — AES-256 key for balance encryption (owner-only)
- `security.log` — append-only security event log

These are gitignored in practice; do not commit them.
