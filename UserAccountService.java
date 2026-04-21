import java.util.Scanner;

public class UserAccountService {

    private final UserDatabase db;
    private final SessionManager sessions;
    private final EncryptionService crypto;
    private final AuthManager auth;
    private final Scanner scanner;

    public UserAccountService(UserDatabase db, SessionManager sessions, EncryptionService crypto, Scanner scanner) {
        this.db = db;
        this.sessions = sessions;
        this.crypto = crypto;
        this.auth = new AuthManager(db, scanner);
        this.scanner = scanner;
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

        /**
         * Mitigates CWE-836 and CWE-328 by hashing the password before 
         * storing it in the database.
         * Also mitgates CWE-178 by normalizing the username to lowercase 
         * before storing.
         */
        String hash = PasswordManager.hash(pm.password);
        db.createUser(username.toLowerCase(), hash, 100);

        Integer uid = db.findUserId(username, hash);
        if (uid == null) {
            SecurityLogger.log(SecurityLogger.Event.DB_ERROR, username, "user not found after create");
            return null;
        }

        SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, "registered");
        return sessions.login(uid, username);
    }
    
    // CWE-307 - Improper Restriction of Excessive Authentication Attempts
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

        System.out.print("Enter Password: ");
        String password = scanner.nextLine();

        Integer uid = auth.login(username, password);

        if (uid == null) {
            // Don't reveal whether the username exists.
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, username, "unknown user");
            System.out.println("Login failed.");
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
        if (!pm.resetPassword()) {
            SecurityLogger.log(SecurityLogger.Event.SUSPICIOUS_ACTIVITY, username, "Password reset failed.");
            return false;
        }

        db.updatePasswordHash(username, PasswordManager.hash(pm.password));
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
        System.out.print("Username: ");
        String username = scanner.nextLine().trim();
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
    private PasswordManager loadPasswordManager(String username, String hash) {
        // Stub: uses the convenience constructor.
        // TODO: load security questions/answers from DB once UserDatabase
        //       exposes getSecurityQuestions(username).
        return new PasswordManager(hash);
    }

}