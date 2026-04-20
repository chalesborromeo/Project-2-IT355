import java.util.Scanner;

// Demo wiring for Charles's CWE modules. This ties the existing
// SlotMachine game into a login / session / audit-logged flow so
// each of the 5 CWEs can be observed end-to-end.
public class Main {
    private static final int STAKE = 5;

    public static void main(String[] args) throws Exception {
        EncryptionService crypto = new EncryptionService();
        SessionManager sessions = new SessionManager();

        try (UserDatabase db = new UserDatabase(crypto);
            Scanner in = new Scanner(System.in)) {

            System.out.println("1) Register new account");
            System.out.println("2) Log in");
            System.out.print("> ");
            String choice = in.nextLine().trim();

            String user;
            String pass;
            Integer uid;

            if (choice.equals("1")) {
                System.out.print("new username: ");
                user = in.nextLine().trim();
                System.out.print("new password: ");
                pass = in.nextLine().trim();
                if (user.isEmpty() || pass.isEmpty()) {
                    System.out.println("Username and password cannot be empty.");
                    return;
                }
                if (db.usernameExists(user)) {
                    System.out.println("Username already taken.");
                    return;
                }
                // stub replaced with mitigation of CWE-836 and 
                // CWE-328 by hashing the password properly before storing
                db.createUser(user, PasswordManager.hash(pass), 100);
                AuthManager auth = new AuthManager(db);
                uid = auth.login(user, pass);
                System.out.println("Account created. Logging in...");
            } else {
                System.out.print("username: ");
                user = in.nextLine().trim();
                System.out.print("password: ");
                pass = in.nextLine().trim();
                uid = db.findUserId(user, PasswordManager.hash(pass));
            }

            if (uid == null) {
                SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, user, null);
                System.out.println("Login failed.");
                return;
            }
            SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, user, null);
            String sid = sessions.login(uid, user);

            SlotMachine machine = new SlotMachine(STAKE);
            while (true) {
                SessionManager.Session s = sessions.validate(sid);
                if (s == null) {
                    System.out.println("Session expired — please log in again.");
                    break;
                }
                int balance = db.getBalance(s.userId());
                System.out.println("Balance: " + balance);
                System.out.print("spin / quit > ");
                String cmd = in.nextLine().trim();
                if (cmd.equalsIgnoreCase("quit")) break;
                if (!cmd.equalsIgnoreCase("spin")) continue;
                if (balance < STAKE) {
                    System.out.println("Out of credits.");
                    break;
                }

                int winnings = machine.Spin();
                int newBalance = balance - STAKE + winnings;
                db.updateBalance(s.userId(), newBalance);
                db.recordSpin(s.userId(), STAKE, winnings);

                // Flag unusually large wins for manual review (CWE-778).
                if (winnings >= STAKE * 7) {
                    SecurityLogger.log(SecurityLogger.Event.LARGE_WIN, user,
                            "stake=" + STAKE + " winnings=" + winnings);
                }
            }
            sessions.logout(sid);
        }
    }
}