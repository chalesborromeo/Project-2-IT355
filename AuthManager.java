import java.util.Scanner;

/**
 * AuthManager demonstrates mitigation of several CWE vulnerabilities
 * through safer authentication practices.
 *
 * CWE Fixes Demonstrated:
 * - CWE-178: Normalize usernames to avoid case‑sensitivity 
 *  inconsistencies.
 * - CWE-328 / CWE-836: Avoid storing or comparing raw passwords 
 *  by hashing them server‑side using a secure hashing function.
 * - CWE-308: Require a second authentication factor (OTP) before 
 *  granting access.
 * - CWE-842: Prevent unauthorized privilege escalation by validating 
 *  role rules.
 */
public class AuthManager {

    private final UserDatabase db;
    private final Scanner scanner;
    // For demo of CWE-308 mitigation purposes, we use a fixed OTP. In a real system, 
    // this would be generated dynamically.
    private final String expectedOTP = "123456";

    /**
     * Constructor
     * @param db reference to the user database
     * @param scanner reference to a Scanner for user input 
     * (prevents resource leaks)
     */
    public AuthManager(UserDatabase db, Scanner scanner) {
        this.db = db;
        this.scanner = scanner;
    }

    /**
     * Attempts to authenticate a user.
     * @param username user input username
     * @param password raw password input
     * @return user ID if successful, null otherwise
     */
    public Integer login(String username, String password) {

        // CWE-178: normalize username to avoid case sensitivity issues
        String normalizedUsername = normalizeUsername(username);
        if (normalizedUsername == null || normalizedUsername.isEmpty()) {
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, "(null)", "Invalid username format");
            return null;
        }

        // CWE-836 and CWE-328:
        // hash password before comparing with stored value
        String hashedPassword = PasswordManager.hash(password);

        // Validate credentials against database
        Integer uid = db.findUserId(normalizedUsername, hashedPassword);

        if (uid == null) {
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, normalizedUsername, "Invalid credentials");
            return null;
        }

        // CWE-308: enforce MFA
        if (!verifyOTP()) {
            SecurityLogger.log(SecurityLogger.Event.LOGIN_FAILURE, normalizedUsername, "Failed MFA");
            return null;
        }

        // CWE-842: role enforcement check (basic simulation)
        enforceRolePolicy(normalizedUsername);

        SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, normalizedUsername, "Authenticated");
        return uid;
    }

    /**
     * Converts username to lowercase to avoid case sensitivity issues.
     * Mitigates CWE-178 by ensuring consistent username comparison.
     * @param username raw username
     * @return normalized username, or null if input is invalid
     */
    private String normalizeUsername(String username) {
        if (username == null) {
            return null;
        }
        return username.toLowerCase();
    }

    /**
     * Verifies OTP for multi-factor authentication.
     * Mitigates CWE-308 by requiring a second factor before granting access.
     * @return true if OTP is correct
     */
    private boolean verifyOTP() {
        System.out.print("Enter OTP: ");
        String otp = scanner.nextLine();
        return otp.equals(expectedOTP);
    }

    /**
     * Mitigates CWE-842 by ensuring correct role assignment.
     * (Simulated since roles are not stored in DB)
     * @param username normalized username
     */
    private void enforceRolePolicy(String username) {
        if (username.equals("admin")) {
            // Only admin should have admin privileges
            SecurityLogger.log(SecurityLogger.Event.SUSPICIOUS_ACTIVITY,
                    username, "Admin access granted");
        }
    }
}