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


    // forgot password - account recovery logic, should take the user's new password and hash


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
