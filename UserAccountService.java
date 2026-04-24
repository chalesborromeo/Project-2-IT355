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

        PasswordManager pm = new PasswordManager(crypto, scanner);

        /**
         * Mitigates CWE-836 and CWE-328 by hashing the password before
         * storing it in the database.
         * Also mitgates CWE-178 by normalizing the username to lowercase
         * before storing.
         */
        String hash = pm.getPasswordHash();
        String normalized = username.toLowerCase();
        db.createUser(normalized, hash, 100);
        db.updateSecurityQA(normalized, pm.getSecurityQuestions(), decryptAnswers(pm.getEncryptedAnswers()));

        Integer uid = db.findUserId(normalized, hash);
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

        // CWE - 480 - Joey Pina - (Use of Incorrect Operator): Using the correct operator ensures expected barrier. In this case if
        // the operator was incorrect, assignment instead of comparison, we would make security incredibly
        // vulnerable because hash would then be null. Causing possible hash protected passwords 
        // become vulnerable and / or unexpected data. 
        if (hash == null) {
            // Same response regardless of whether the account exists.
            System.out.println("If that account exists, a reset has been initiated.");
            return false;
        }

        PasswordManager pm = loadPasswordManager(username, hash);
        if (pm == null || !pm.resetPassword()) {
            SecurityLogger.log(SecurityLogger.Event.SUSPICIOUS_ACTIVITY, username, "Password reset failed.");
            return false;
        }

        // DB + session updates happen inside pm.resetPassword() now
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
     */
    private PasswordManager loadPasswordManager(String username, String hash) {
        String normalized = username.toLowerCase();
        String[] questions = db.getSecurityQuestions(normalized);
        String[] plain     = db.getSecurityAnswers(normalized);
        if (questions == null || plain == null) return null;

        // Re-encrypt with fresh IVs so PasswordManager holds ciphertext in memory.
        String[] encrypted = new String[plain.length];
        for (int i = 0; i < plain.length; i++) encrypted[i] = crypto.encrypt(plain[i]);

        return new PasswordManager(crypto, db, sessions, scanner,
                normalized, hash, java.time.LocalDate.now(), questions, encrypted);
    }

    private String[] decryptAnswers(String[] encrypted) {
        String[] plain = new String[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) plain[i] = crypto.decrypt(encrypted[i]);
        return plain;
    }

}