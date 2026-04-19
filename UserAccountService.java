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

    
    // log out - will allow users to log out and properly invalidate the current session


    // prompt username - simple username entry 


    // load password manager - reconstructs passwordManager backed with the stored credentials
        // this would be swapped for a proper database backed construction


    // hash - should be able to hash a password
}
