import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Scanner;

public class PasswordManager {
	String passwordHash;
	LocalDate creationDate;
	String[] secQuestions = new String[5];
	String[] encryptedAnswers = new String[5];

	private final Scanner input;
	private final EncryptionService crypto;
	private final UserDatabase db;             // null during registration
	private final SessionManager sessions;     // null during registration
	private String username;

	// CWE-613: short-lived gate on the password-reset flow
	private static final long RESET_TOKEN_TTL_MS = 5L * 60 * 1000;
	private final SecureRandom rng = new SecureRandom();
	private String activeResetToken;
	private long   resetTokenExpiry;

	/**
	 * Registration constructor, requires user input
	 */
	PasswordManager(EncryptionService crypto, Scanner input){
		this.crypto = crypto;
		this.input = input;
		this.db = null;
		this.sessions = null;
		setPassword();
		setQuestions();
		creationDate = LocalDate.now();
	}

	/**
	 * Load-from-DB constructor, used by the login / reset flow.
	 */
	PasswordManager(EncryptionService crypto, UserDatabase db, SessionManager sessions,
			Scanner input, String username, String passwordHash, LocalDate creationDate,
			String[] secQuestions, String[] encryptedAnswers){
		this.crypto           = crypto;
		this.db               = db;
		this.sessions         = sessions;
		this.input            = input;
		this.username         = username;
		this.passwordHash     = passwordHash;
		this.creationDate     = creationDate;
		this.secQuestions     = secQuestions;
		this.encryptedAnswers = encryptedAnswers;
	}

	/**
	 * Hashes a password using SHA-256.
	 * Mitigates CWE-328 by ensuring a strong hashing algorithm is used
	 * @param password the raw password to hash
	 * @return the hashed password as a hex string
	 */
	public static String hash(String password) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hashBytes = md.digest(password.getBytes("UTF-8"));
			StringBuilder sb = new StringBuilder();
			for (byte b : hashBytes) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		}
		catch (Exception e) {
			throw new RuntimeException("Error hashing password", e);
		}
	}

	public String getPasswordHash()       { return passwordHash; }
	public String[] getSecurityQuestions(){ return secQuestions.clone(); }
	public String[] getEncryptedAnswers() { return encryptedAnswers.clone(); }

	/**
	 * Login sequence, allows 3 attempts before password reset
	 * @return whether the login was successful
	 */
	public boolean loginAttempt() {
		System.out.println("Enter Password:");
		if (matches(input.nextLine())) {
			return checkAge();
		}

		int attempts = 2;
		while (attempts > 0) {
			System.out.println("Incorrect password. Try again. Attempts remaining: " + attempts);
			System.out.println("Enter Password:");
			if (matches(input.nextLine())) {
				return checkAge();
			}
			attempts--;
		}

		SecurityLogger.log(SecurityLogger.Event.ACCOUNT_LOCKED, username, "3 failed attempts");
		System.out.print("Would you like to reset your password? Y/N: ");
		if (input.nextLine().trim().equalsIgnoreCase("y")) {
			return resetPassword();
		}

		return false;
	}

	// Constant-time hash comparison (avoids timing side-channel)
	private boolean matches(String candidate) {
		byte[] a = hash(candidate).getBytes(StandardCharsets.UTF_8);
		byte[] b = passwordHash.getBytes(StandardCharsets.UTF_8);
		return MessageDigest.isEqual(a, b);
	}

	/**
	 * If password is over 70 days old, issues a warning. If over 90, forces a password rest.
	 * @return
	 */
	private boolean checkAge() {
		LocalDate now = LocalDate.now();
		if(now.isAfter(creationDate.plusDays(90))) {
			System.out.println("Your password is expired. Please reset it.");
			return resetPassword();
		}
		else if(now.isAfter(creationDate.plusDays(70)))
			System.out.println("Your password is nearing expiration. Please reset it soon.");
		return true;
	}

	/**
	 * Password reset sequence, using security questions
	 * @return whether the password was successfully reset
	 */
	public boolean resetPassword() {
		if(!securityQuestions()) {
			SecurityLogger.log(SecurityLogger.Event.SUSPICIOUS_ACTIVITY, username,
					"failed security questions");
			return false;
		}

		// CWE-613: the recovery gate closes after 5 minutes
		String token = issueResetToken();
		System.out.println("Security check passed. You have 5 minutes to set a new password.");
		System.out.println("Enter new password:");
		String candidate = input.nextLine();
		if (!consumeResetToken(token)) {
			SecurityLogger.log(SecurityLogger.Event.SESSION_EXPIRED, username,
					"reset token expired");
			System.out.println("Reset token expired. Please start over.");
			return false;
		}
		passwordHash = hash(candidate);

		System.out.print("Would you like to update your security questions? Y/N ");
		if(input.nextLine().trim().equalsIgnoreCase("y"))
			setQuestions();

		creationDate = LocalDate.now();

		if (db != null && username != null) {
			db.updatePasswordHash(username, passwordHash);
			db.updateSecurityQA(username, secQuestions, decryptedAnswers());
		}
		// CWE-384-adjacent: stale sessions must not outlive a credential change
		if (sessions != null && username != null) {
			sessions.logoutAll(username);
		}
		SecurityLogger.log(SecurityLogger.Event.LOGIN_SUCCESS, username, "password reset");
		return true;
	}

	/**
	 * Asks the security questions
	 *
	 * @return whether the answers were all correct
	 */
	private boolean securityQuestions() {
		for (int i = 0; i < 5; i++) {
			System.out.println("Question " + (i + 1) + ": " + secQuestions[i]);
			System.out.print("Answer: ");
			String provided = input.nextLine();
			String stored   = crypto.decrypt(encryptedAnswers[i]);
			byte[] a = provided.getBytes(StandardCharsets.UTF_8);
			byte[] b = stored.getBytes(StandardCharsets.UTF_8);
			if (!MessageDigest.isEqual(a, b)) {
				return false;
			}
			if (i == 4) return true;
		}
		return false;
	}

	/**
	 * Sets the password. Only the hash is retained (CWE-312).
	 */
	//TODO Needs encryption
    private void setPassword() {
        System.out.println("Enter new password:");
        password = input.nextLine();
    }

	/**
	 * Sets the security questions and answers. Answers are encrypted
	 * before being retained (CWE-312).
	 */
	private void setQuestions() {
		System.out.println("Please enter 5 security questions and their answers.");
		for (int i = 0; i < 5; i++) {
			System.out.println("Question " + (i + 1) + ": ");
			secQuestions[i] = input.nextLine();
			System.out.print("Answer: ");
			encryptedAnswers[i] = crypto.encrypt(input.nextLine());
		}
	}

	private String issueResetToken() {
		byte[] bytes = new byte[16];
		rng.nextBytes(bytes);
		activeResetToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		resetTokenExpiry = System.currentTimeMillis() + RESET_TOKEN_TTL_MS;
		return activeResetToken;
	}

	private boolean consumeResetToken(String token) {
		if (activeResetToken == null || !activeResetToken.equals(token)) return false;
		boolean valid = System.currentTimeMillis() <= resetTokenExpiry;
		activeResetToken = null;
		return valid;
	}

	private String[] decryptedAnswers() {
		String[] out = new String[encryptedAnswers.length];
		for (int i = 0; i < encryptedAnswers.length; i++) {
			out[i] = crypto.decrypt(encryptedAnswers[i]);
		}
		return out;
	}

	/**
	 * Debug method. Makes a password's date outdated.
	 */
	public void timeSkip() {
		creationDate = creationDate.minusDays(100);
	}

}
