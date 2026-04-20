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

            UserAccountService accountService = new UserAccountService(db, sessions, crypto, in);

            System.out.println("1) Register new account");
            System.out.println("2) Log in");
            System.out.println("3) Forgot password");
            System.out.print("> ");
            String choice = in.nextLine().trim();

            String sid = null;

            switch (choice) {
                case "1" -> sid = accountService.register();
                case "2" -> sid = accountService.login();
                case "3" -> {
                    System.out.print("Username: ");
                    String username = in.nextLine().trim();
                    accountService.forgotPassword(username);
                    System.out.println("Please log in with your new password.");
                    sid = accountService.login();
                }
                default -> {
                    System.out.println("Invalid option.");
                    return;
                }
            }

            if (sid == null) {
                System.out.println("Could not start session. Exiting.");
                return;
            }

            // Game loop — session validated on every spin.
            SlotMachine machine = new SlotMachine(STAKE);
            while (true) {
                SessionManager.Session s = accountService.validateSession(sid);
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
                    SecurityLogger.log(SecurityLogger.Event.LARGE_WIN, s.username(),
                            "stake=" + STAKE + " winnings=" + winnings);
                }
            }

            accountService.logout(sid);
        }
    }
}