import java.time.LocalDate;
import java.util.Scanner;

//TODO Many methods will need encryption.
public class PasswordManager {
	String password;
	LocalDate creationDate;
	String[] secQuestions = new String[5];
	String[] secAnswers = new String[5];
	
	
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
	 * Login sequence, allows 3 attempts before password reset
	 * @return whether the login was successful
	 */
	//TODO Needs encryption
	public boolean loginAttempt() {
		Scanner input = new Scanner(System.in);
		System.out.println("Enter Password:");
		
		if(input.nextLine().equals(password)) {
			input.close();
			return true;
		}
		int attempts = 2;
		while(attempts>0) {
			System.out.println("Incorrect password. Try again. Attempts remaining: "+attempts);
			System.out.println("Enter Password:");
			if(input.nextLine().equals(password)) {
				input.close();
				return checkAge();
			}
			attempts--;
		}
		
		System.out.print("Would you like to reset your password? Y/N");
		if(input.next().equalsIgnoreCase("y")) {
			input.close();
			return resetPassword();
		}
		
		input.close();
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
		Scanner input = new Scanner(System.in);
		for(int i=0;i<5;i++) {
			System.out.println("Question "+(i+1)+": "+secQuestions[i]);
			
			System.out.println("Answer: ");
			if(secAnswers[i].equals(input.nextLine())) { 
				if(i==4) {
					input.close();
					return true;
				}
			}
			else break;
		}
		input.close();
		return false;
	}
	
	/**
	 * Sets the password.
	 */
	//TODO Needs encryption
	private void setPassword() {
		Scanner input = new Scanner(System.in);
		System.out.println("Enter new password:");
		password = input.nextLine();
		input.close();
	}

	/**
	 * Sets the security questions and answers.
	 */
	//TODO needs encryption for answers
	private void setQuestions() {
		Scanner input = new Scanner(System.in);
		
		System.out.println("Please enter 5 security questions and their answers.");
		for(int i=0;i<5;i++) {
			System.out.println("Question "+(i+1)+": ");
			secQuestions[i] = input.nextLine();
			System.out.println("Answer: ");
			secAnswers[i] = input.nextLine();
		}
		
		input.close();
	}
	
	/**
	 * Debug method. Makes a password's date outdated.
	 */
	public void timeSkip() {
		creationDate = creationDate.minusDays(100);
	}
	
}
