public class SlotMachine {
	private int stakes;
	SlotMachine(int stake){
		stakes = stake;
	}
	
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
	
	public int riggedSpin(int outcome) {
		//Selecting wheel outcomes
		char wheels[] = new char[4];
		for(int i=0;i<3;i++)
			wheels[i] = spinWheel();
		wheels[3] = specialWheel();
		//Guaranteeing win
			int change = (int)Math.random()*3;
			switch(change) {
			case 0:
				wheels[0]=wheels[1];
			case 1:
				wheels[1]=wheels[2];
			case 2:
				wheels[0]=wheels[2];
			}
		
		System.out.println("-------------");
		System.out.println("|"+wheels[0]+"|"+
		wheels[1]+"|"+wheels[2]+"|"+wheels[3]+"|");			
		System.out.println("-------------");
			
		//Checking win conditions
		return results(wheels);
	}
	
	private int results(char[] wheels) {
		double score = 0;
		//All 3 match
		if(wheels[0] == wheels[1]&&wheels[1] == wheels[2]) {
			
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
			for(int i=0;i<3;i++) {
				switch(wheels[i]) {
				case 'L':
					if(1>highestValue) {
						highestValue = 1;
						wheelslot = i;
					}
				case 'G':
					if(2>highestValue) {
						highestValue = 2;
						wheelslot = i;
					}
				case 'B':
					if(3>highestValue) {
						highestValue = 3;
						wheelslot = i;
					}
				case '7':
					if(4>highestValue) {
						highestValue = 4;
						wheelslot = i;
					}
				default:
					if(1>highestValue) {
						highestValue = 1;
						wheelslot = i;
					}
				}
			}
			System.out.print("Wildcard! Two ");
			score = twoMatch(wheels[wheelslot]);
		}
		
		//No matches or wildcard, just cherry
		else if(wheels[0]=='C'||wheels[1]=='C'||wheels[2]=='C') {
			System.out.println("Just a cherry. +"+stakes*0.4);
			score += stakes*0.5;
		}
		
		return (int)score;
	}
	
	private char spinWheel() {
		int r = (int)Math.random()*5;
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
			return 'L'; //This shouldn't happen
		}
	}
	
	private char specialWheel() {
		int r = (int)Math.random()*4;
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
			return '1'; //This shouldn't happen
		}
	}
	
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
