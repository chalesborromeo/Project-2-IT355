
import java.security.SecureRandom;

/**
 * Adheres to 
 * CWE-1241 - Use of Predictable Algorithm in Random Number Generator
 * CWE-342 - Predictable Exact Value from Previous Values
 * CWE-343 - Predictable Value Range from Previous Values
 * CWE-341 - Predictable from Observable State
 * Through the use of a TRNG instead of a PRNG
 */
public class SlotMachine {
	private int stakes;
	private final SecureRandom rand = new SecureRandom();
	/**
	 * Constructs a new slot machine
	 * 
	 * @param stake The base amount of score the machine gives
	 */
	SlotMachine(int stake){
		stakes = stake;
	}
	/**
	 * Simulates a spinning all wheels of the slot machine
	 * 
	 * @return the total result of the spin
	 */
	public int Spin() {
		//Selecting wheel outcomes
		char wheels[] = new char[4];
		for(int i=0;i<3;i++)
			wheels[i] = spinWheel();
		wheels[3] = specialWheel();
		
		System.out.println("-------------");
		System.out.println("|"+wheels[0]+"|"+
		wheels[1]+"|"+wheels[2]+"|"+wheels[3]+"|");
		System.out.println("-------------");
		
		//Checking win conditions
		return results(wheels);
	}
	/**
	 * Simulates a spin with a predetermined outcome
	 * 
	 * @param outcome 1 represents a win, 0 represents a loss
	 * 
	 * @return the total result of the rigged spin
	 */
	public int riggedSpin(int outcome) {
		//Selecting wheel outcomes
		char wheels[] = new char[4];
		for(int i=0;i<3;i++)
			wheels[i] = spinWheel();
		wheels[3] = specialWheel();
		if(outcome==1) {
		//Guaranteeing win
			int change = (int)(rand.nextInt(3));
			switch(change) {
			case 0:
				wheels[0]=wheels[1];
				break;
			case 1:
				wheels[1]=wheels[2];
				break;
			case 2:
				wheels[0]=wheels[2];
				break;
			}
			}
		else if(outcome==0) {
		//Guaranteeing loss
			wheels[3]='1';
			while(wheels[0]==wheels[1]||wheels[1]==wheels[2]||wheels[0]==wheels[2]) {
				for(int i=0;i<3;i++)
					wheels[i] = spinWheel();
			}
		}
		
		System.out.println("---------");
		System.out.println("|"+wheels[0]+"|"+
		wheels[1]+"|"+wheels[2]+"|"+wheels[3]+"|");			
		System.out.println("---------");
			
		//Checking win conditions
		return results(wheels);
	}
	/**
	 * Outputs the results of given a set of wheels
	 * 
	 * @param wheels the character values of the wheels
	 * 
	 * @return the final score of the given wheels
	 */
	private int results(char[] wheels) {
		double score = 0;
		//All 3 match
		if(wheels[0] == wheels[1]&&wheels[1] == wheels[2]) {
			score += threeMatch(wheels[0]);
		}
		
		//Only 2 match
		else if(wheels[0]==wheels[1]||wheels[0]==wheels[2]||wheels[1]==wheels[2]) {
			char matching='.';
			if(wheels[0]==wheels[1]||wheels[0]==wheels[2])
				matching=wheels[0];
			else matching = wheels[1];
					
			//No Wildcard
			if(wheels[3]!='*') {
				score += twoMatch(matching);
			}
			//Wildcard
			else {
				System.out.print("Wildcard! ");
				score+=threeMatch(matching);
			}
		}
		//No matches, wildcard
		else if(wheels[3]=='*') {
			int wheelslot = 0;
			int highestValue = 0;

			// CWE - 1095 - Joey Pina - (Loop Condition Value Update within the Loop): By having a loop's condition not update inside the same loop we are avoiding 
			// unpredictable and / or infinite behaviour. This ensures ease of maintainability, although not entirely security, 
			// it ensures this usage eases the debugging process and reduces potential areas of concern
			for(int i=0;i<3;i++) {
				switch(wheels[i]) {
				case 'L':
					if(1>highestValue) {
						highestValue = 1;
						wheelslot = i;
						break;
					}
				case 'G':
					if(2>highestValue) {
						highestValue = 2;
						wheelslot = i;
						break;
					}
				case 'B':
					if(3>highestValue) {
						highestValue = 3;
						wheelslot = i;
						break;
					}
				case '7':
					if(4>highestValue) {
						highestValue = 4;
						wheelslot = i;
						break;
					}
				default:
					if(1>highestValue) {
						highestValue = 1;
						wheelslot = i;
						break;
					}
				}
			}
			System.out.print("Wildcard! ");
			score = twoMatch(wheels[wheelslot]);
		}
		
		//No matches or wildcard, just cherry
		else if(wheels[0]=='C'||wheels[1]=='C'||wheels[2]=='C') {
			System.out.println("Just a cherry. +"+stakes*0.4);
			score += stakes*0.5;
		}
		
		if(score==0) 
			System.out.println("No prize...");
		
		else if(wheels[3]=='2') {
			System.out.println("x2 Bonus!");
			score *= 2;
		}
		else if(wheels[3]=='3') {
			System.out.println("3x Bonus!");
			score *= 3;
		}
		
		return (int)score;
	}
	/**
	 * Simulates spinning one wheel on the slot machine
	 * 
	 * @return A character coresponding to a symbol on the wheel
	 */
	private char spinWheel() {
		int r = (int)(rand.nextInt(5));
		switch(r) {
		case 0: 
			return 'C'; //For 'Cherry'
		case 1:
			return 'L'; //For 'Lemon'
		case 2:
			return 'G'; //For 'Grapes'
		case 3:
			return 'B'; //For 'Bells'
		case 4:
			return '7'; 
		default:
			return '0'; //This shouldn't happen
		}
	}
	/**
	 * Simulates spining the special wheel
	 * 
	 * @return A character representing the landed on symbol
	 */
	private char specialWheel() {
		int r = (int)(rand.nextInt(4));
		switch(r) {
		case 0: 
			return '1'; //Standard
		case 1:
			return '*'; //Wildcard
		case 2:
			return '2'; //x2 earnings
		case 3:
			return '3'; //x3 earnings
		default:
			return '0'; //This shouldn't happen
		}
	}
	/**
	 * Returns the value of 3 matched symbols
	 * 
	 * @param matched The character that has been matched 3 times in a row
	 * 
	 * @return A double representing the amount gained
	 */
	private double threeMatch(char matched) {
		System.out.print("Three ");
		switch(matched) {
		case 'C': //For 'Cherry'
			System.out.println("Cherries! +"+stakes*4);
			return stakes*4;
			
		case 'L': //For 'Lemon'
			System.out.println("Lemons! +"+stakes*4.5);
			return stakes*4.5;
			
		case 'G': //For 'Grapes'
			System.out.println("Grapes! +"+stakes*5);
			return stakes*5;
			
		case 'B': //For 'Bells'
			System.out.println("Bells! +"+stakes*5.5);
			return stakes*5.5;
			
		case '7':
			System.out.println("Sevens! +"+stakes*7);
			return stakes*7; 
		default: //This shouldn't happen
			return 0;
		}
	}
	/**
	 * Returns the value of 2 matched symbols
	 * 
	 * @param matched The character that has been matched 2 times in a row
	 * 
	 * @return A double representing the amount gained
	 */
	private double twoMatch(char matched) {
		System.out.print("Two ");
		switch(matched) {
		case 'C': //For 'Cherry'
			System.out.println("Cherries! +"+stakes*4);
			return stakes*1;
			
		case 'L': //For 'Lemon'
			System.out.println("Lemons! +"+stakes*4.5);
			return stakes*1.25;
			
		case 'G': //For 'Grapes'
			System.out.println("Grapes! +"+stakes*5);
			return stakes*1.5;
			
		case 'B': //For 'Bells'
			System.out.println("Bells! +"+stakes*5.5);
			return stakes*1.75;
			
		case '7':
			System.out.println("Sevens! +"+stakes*7);
			return stakes*2.5; 
		default: //This shouldn't happen
			return 0;
		}
	}
}
