public class UserAccountService {

    private final UserDatabase db;
    private final SessionManager sessions;
    private final EncryptionService crypto;

    public UserAccountService(UserDatabase db, SessionManager sessions, EncryptionService crypto) {
        this.db = db;
        this.sessions = sessions;
        this.crypto = crypto;
    }

    /**
     * Registers a new user.
     * Uses PasswordManager to collect and validate the password and security
     * questions interactively, then persists the hashed credentials.
     *
     * @return session ID if registration + auto-login succeeded, null otherwise
     */
    public String register() {
        String username = promptUsername();
        if (username == null) return null;

        if (db.usernameExists(username)) {
            System.out.println("Username already taken.");
            return null;
        }

        PasswordManager pm = new PasswordManager();

        String hash = hash(pm.password);
        db.createUser(username, hash, 100);

        Integer uid = db.findUserId(username, hash);
        if (uid == null) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, "user not found after create");
            return null;
        }

        SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, "registered");
        return sessions.login(uid, username);
    }

    /**
     * Logs in an existing user.
     * Delegates the interactive login attempt (3 tries, age check) to
     * PasswordManager, then verifies the resulting hash against the database.
     *
     * @return session ID on success, null on failure
     */
    public String login() {
        String username = promptUsername();
        if (username == null) return null;

        String hash = db.getPasswordHash(username);
        if (hash == null) {
            // Don't reveal whether the username exists.
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, username, "unknown user");
            System.out.println("Login failed.");
            return null;
        }

        // Reconstruct a PasswordManager with the stored hash so loginAttempt()
        // can compare against it. Security Qs are loaded from the DB.
        PasswordManager pm = loadPasswordManager(username, hash);
        if (pm == null) return null;

        boolean ok = pm.loginAttempt();
        if (!ok) {
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, username, null);
            System.out.println("Login failed.");
            return null;
        }

        // If loginAttempt triggered a reset internally, persist the new hash.
        String currentHash = hash(pm.password);
        if (!currentHash.equals(hash)) {
            db.updatePasswordHash(username, currentHash);
            SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, "post-reset login");
        }

        Integer uid = db.findUserId(username, currentHash);
        if (uid == null) {
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, username, "hash mismatch after reset");
            return null;
        }

        SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, null);
        return sessions.login(uid, username);
    }

    /**
     * Explicit forgot-password / account-recovery flow.
     * Runs PasswordManager's security question gate and, on success,
     * persists the new password hash to the database.
     *
     * @return true if the reset completed successfully
     */
    public boolean forgotPassword(String username) {
        String hash = db.getPasswordHash(username);
        if (hash == null) {
            // Same response regardless of whether the account exists.
            System.out.println("If that account exists, a reset has been initiated.");
            return false;
        }

        PasswordManager pm = loadPasswordManager(username, hash);
        if (pm == null) return false;

        boolean ok = pm.resetPassword();
        if (!ok) {
            SecurityLogger.log(SecurityLogger.Event.SUSPICIOUS_ACTIVITY, username,
                    "failed password reset attempt");
            System.out.println("Reset failed — security questions incorrect.");
            return false;
        }

        db.updatePasswordHash(username, hash(pm.password));
        SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, "password reset");
        System.out.println("Password reset successfully.");
        return true;
    }

    /**
     * Validates an active session. Delegates to SessionManager.
     * Returns null and logs if the session is missing or expired.
     */
    public SessionManager.Session validateSession(String sid) {
        return sessions.validate(sid);
    }

    /**
     * Logs out and invalidates the session.
     */
    public void logout(String sid) {
        sessions.logout(sid);
    }

    /**
     * Prompts for a username via stdin.
     * Returns null if the input is empty.
     */
    private String promptUsername() {
        java.util.Scanner in = new java.util.Scanner(System.in);
        System.out.print("Username: ");
        String username = in.nextLine().trim();
        if (username.isEmpty()) {
            System.out.println("Username cannot be empty.");
            return null;
        }
        return username;
    }

    /**
     * Reconstructs a PasswordManager backed by stored credentials.
     * Swap this for a proper DB-backed construction once PasswordManager
     * supports injected state.
     */
    private PasswordManager loadPasswordManager(String username, String storedHash) {
        // Stub: uses the convenience constructor.
        // TODO: load security questions/answers from DB once UserDatabase
        //       exposes getSecurityQuestions(username).
        return new PasswordManager(storedHash);
    }

    /**
     * Hashes a plaintext password.
     * Placeholder matching the hashStub in Main — replace with Rachel's
     * CWE-836 salted hash implementation.
     */
    private static String hash(String password) {
        return "stub:" + password;
    }
}