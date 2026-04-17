import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

// CWE-384 (Session Fixation): on every successful login any prior
// session belonging to that user is invalidated and a fresh,
// cryptographically-random session ID is minted. An attacker who
// planted a session ID on the victim cannot reuse it post-login.
//
// CWE-613 (Insufficient Session Expiration): sessions enforce BOTH
// an idle timeout (inactivity-based) and an absolute timeout (total
// lifetime, regardless of activity) so a leaked token cannot be
// used forever.
public class SessionManager {
    public static final long IDLE_TIMEOUT_MS     = 15L * 60 * 1000;   // 15 min
    public static final long ABSOLUTE_TIMEOUT_MS = 60L * 60 * 1000;   // 1 hr

    private static final int SESSION_ID_BYTES = 32;
    private final SecureRandom rng = new SecureRandom();
    private final Map<String, Session> sessions = new HashMap<>();

    public static final class Session {
        private final int userId;
        private final String username;
        private final long createdAt;
        private long lastActivity;

        Session(int userId, String username) {
            this.userId = userId;
            this.username = username;
            this.createdAt = System.currentTimeMillis();
            this.lastActivity = this.createdAt;
        }

        public int userId() { return userId; }
        public String username() { return username; }
    }

    // CWE-384: destroy any existing session for this user, then mint a
    // fresh ID. Never trust a session ID that existed before login.
    public synchronized String login(int userId, String username) {
        sessions.values().removeIf(s -> s.userId == userId);
        String sid = newSessionId();
        sessions.put(sid, new Session(userId, username));
        SecurityLogger.log(SecurityLogger.Event.SESSION_CREATED, username, "sid=" + shorten(sid));
        return sid;
    }

    // Returns the active session, or null if missing / expired.
    public synchronized Session validate(String sid) {
        Session s = sessions.get(sid);
        if (s == null) {
            SecurityLogger.log(SecurityLogger.Event.SESSION_INVALID, null, "sid=" + shorten(sid));
            return null;
        }
        long now = System.currentTimeMillis();
        // CWE-613: both windows must be within limits.
        if (now - s.createdAt > ABSOLUTE_TIMEOUT_MS || now - s.lastActivity > IDLE_TIMEOUT_MS) {
            sessions.remove(sid);
            SecurityLogger.log(SecurityLogger.Event.SESSION_EXPIRED, s.username, "sid=" + shorten(sid));
            return null;
        }
        s.lastActivity = now;
        return s;
    }

    public synchronized void logout(String sid) {
        Session s = sessions.remove(sid);
        if (s != null) {
            SecurityLogger.log(SecurityLogger.Event.LOGOUT, s.username, "sid=" + shorten(sid));
        }
    }

    private String newSessionId() {
        byte[] bytes = new byte[SESSION_ID_BYTES];
        rng.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // Only log a prefix of the session ID so the full secret never lands
    // in the security log itself.
    private static String shorten(String sid) {
        if (sid == null) return "-";
        return sid.substring(0, Math.min(8, sid.length())) + "...";
    }
}
