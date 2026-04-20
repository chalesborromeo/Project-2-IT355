import java.time.LocalDate;
import java.util.Scanner;
import java.security.MessageDigest;

//TODO Many methods will need encryption.
public class PasswordManager {
	String password;
	LocalDate creationDate;
	String[] secQuestions = new String[5];
	String[] secAnswers = new String[5];
	
    private final Scanner input = new Scanner(System.in);

	
	/**
	 * Default constructor, requires user input
	 */
	PasswordManager(){
		setPassword();
		setQuestions();
		creationDate = LocalDate.now();
	}
	
	/**
	 * Constructor, does not require user input
	 * @param passInput
	 */
	//TODO Needs encryption
	PasswordManager(String password){
		this.password = password;
		this.creationDate = LocalDate.now();
		secQuestions = new String[]{"q1","q2","q3","q4","q5"};
		secAnswers = new String[]{"a1","a2","a3","a4","a5"};
	}

	PasswordManager(String password, LocalDate creationDate, String[] secQuestions, String[] secAnswers){
		this.password     = password;
		this.creationDate = creationDate;
		this.secQuestions = secQuestions;
		this.secAnswers   = secAnswers;
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
	/**
	 * Login sequence, allows 3 attempts before password reset
	 * @return whether the login was successful
	 */
	//TODO Needs encryption
    public boolean loginAttempt() {
        System.out.println("Enter Password:");
        if (input.nextLine().equals(password)) {
            return checkAge();
        }

        int attempts = 2;
        while (attempts > 0) {
            System.out.println("Incorrect password. Try again. Attempts remaining: " + attempts);
            System.out.println("Enter Password:");
            if (input.nextLine().equals(password)) {
                return checkAge();
            }
            attempts--;
        }

        System.out.print("Would you like to reset your password? Y/N: ");
        if (input.nextLine().trim().equalsIgnoreCase("y")) {
            return resetPassword();
        }

        return false;
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
			return false;
		}
		
		setPassword();
		
		Scanner input = new Scanner(System.in);
		System.out.print("Would you like to update your security questions? Y/N");
		if(input.next().equalsIgnoreCase("y"))
			setQuestions();
		input.close();
		
		creationDate = LocalDate.now();
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
            if (secAnswers[i].equals(input.nextLine())) {
                if (i == 4) return true;
            } else break;
        }
        return false;
    }
	
	/**
	 * Sets the password.
	 */
	//TODO Needs encryption
    private void setPassword() {
        System.out.println("Enter new password:");
		boolean strongPassword = false
		String newPassword = input.nextLine();
		while (!strongPassword){
			if(newPassword.length()>=8&&newPassword.matches(".*\\d.*"))
				strongPassword = true;
			else{
				if(newPassword.length()<8)
					System.out.println("Password requires minimum 8 characters");
				if(!newPassword.matches(".*\\d.*"))
					System.out.println("Password requires a digit");
			}
				
        	Str = input.nextLine();
			if
		}
		password = newPassword;
    }

	/**
	 * Sets the security questions and answers.
	 */
	//TODO needs encryption for answers
    private void setQuestions() {
        System.out.println("Please enter 5 security questions and their answers.");
        for (int i = 0; i < 5; i++) {
            System.out.println("Question " + (i + 1) + ": ");
            secQuestions[i] = input.nextLine();
            System.out.print("Answer: ");
            secAnswers[i] = input.nextLine();
        }
    }
	
	/**
	 * Debug method. Makes a password's date outdated.
	 */
	public void timeSkip() {
		creationDate = creationDate.minusDays(100);
	}
	
}
