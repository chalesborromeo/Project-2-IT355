public class UserAccountService {
    private final UserDatabase db;
    private final SessionManager sessions;
    private final EncryptionService crypto;

    public UserAccountService(UserDatabase db, SessionManager sessions, EncryptionService crypto) {
        this.db = db;
        this.sessions = sessions;
        this.crypto = crypto;
    }

    // register - creating an account (consider security questions, passwords etc,)
    public String register() {
        PasswordManager pm = new PasswordManager(); // prompts user for password + security Qs

        String username = promptUsername();
        if (username == null) return null;

        if (db.usernameExists(username)) {
            System.out.println("Username already taken.");
            return null;
        }

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

    // login - logs in the existing user, 3 tries and age checking
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


    // forgot password - account recovery logic, should take the user's new password and hash
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


    // validate session - validates the active session, should return null if the session is expired
    public SessionManager.Session validateSession(String sid) {
        return sessions.validate(sid);
    }
    
    // log out - will allow users to log out and properly invalidate the current session
    public void logout(String sid) {
        sessions.logout(sid);
    }

    // prompt username - simple username entry 
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

    // load password manager - reconstructs passwordManager backed with the stored credentials
        // this would be swapped for a proper database backed construction
    private PasswordManager loadPasswordManager(String username, String storedHash) {
        // Stub: uses the convenience constructor.
        // TODO: load security questions/answers from DB once UserDatabase
        //       exposes getSecurityQuestions(username).
        return new PasswordManager(storedHash);
    }

    // hash - should be able to hash a password
    private static String hash(String password) {
        return "stub:" + password;
    }
}
