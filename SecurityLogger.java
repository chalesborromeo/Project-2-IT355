import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

// CWE-778 (Insufficient Logging): append-only record of security-relevant
// events so incidents (failed logins, expired sessions, suspicious activity)
// can be reviewed after the fact.
public class SecurityLogger {
    private static final Path LOG_PATH = Paths.get("security.log");
    private static final DateTimeFormatter TS =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss").withZone(ZoneId.systemDefault());

    public enum Event {
        LOGIN_SUCCESS, LOGIN_FAILURE, ACCOUNT_LOCKED,
        SESSION_CREATED, SESSION_REGENERATED, SESSION_EXPIRED,
        SESSION_INVALID, LOGOUT,
        BALANCE_UPDATE, LARGE_WIN, DB_ERROR, SUSPICIOUS_ACTIVITY
    }

    public static synchronized void log(Event event, String actor, String detail) {
        String line = String.format("%s | %s | %s | %s%n",
                TS.format(Instant.now()),
                event.name(),
                actor == null ? "-" : actor,
                detail == null ? "-" : detail);
        try {
            Files.writeString(LOG_PATH, line,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // Last-resort fallback — a failing logger must not crash the app,
            // but we surface it so the operator notices the gap.
            System.err.println("[SecurityLogger] failed to write log: " + e.getMessage());
        }
    }
}
