package cipher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

public class Caesar {

	private static String cipher = "KNXMN SLKWJ XMBFY JWGJS IXFSI FIRNY XBTWI KNXMW FSPTA JWBMJ QRNSL FSDIF D";
	private static char[] mostUsed = { 'E', 'T', 'A', 'O', 'I', 'N' };
	
	private static HashMap<Character, Integer> frequencies = new HashMap<Character, Integer>();
	private static ArrayList<Integer> potentialOffsets = new ArrayList<Integer>();

	public static void main(String[] args) {
		getCharCount();
		setPotentialOffsets();
		printPotentialPlaintexts();
	}

	/**
	 * 
	 * @param cipher
	 *            is a cipher from which to count the occurrence of each
	 *            character.
	 */
	private static void getCharCount() {
		char c;
		for (int i = 0; i < cipher.length(); i++) {
			// temporary storage of characters from cipher.
			c = cipher.charAt(i);
			// omitting white spaces.
			if (c != ' ') {
				// if the character is not in the map, add it.
				if (!frequencies.containsKey(c)) {
					frequencies.put(c, 1);
				} else {
					// otherwise, increment it's count.
					frequencies.put(c, frequencies.get(c) + 1);
				}
			}
		}
	}

	/**
	 * 
	 * @param frequencies
	 *            containing the cypher's character frequencies.
	 * @param mostUsed
	 *            contains the characters which are most frequently used in a
	 *            descending order.
	 */
	private static void setPotentialOffsets() {
		int highestCount = 0;

		Iterator<Entry<Character, Integer>> it = frequencies.entrySet().iterator();
		Entry<Character, Integer> val;

		while (it.hasNext()) {
			val = it.next();
			if (val.getValue() > highestCount)
				highestCount = val.getValue();
		}

		it = frequencies.entrySet().iterator();
		char temp;
		
		while (it.hasNext()) {
			val = it.next();
			if (val.getValue() == highestCount) {
				for (char c : mostUsed) {
					temp = val.getKey();
					if (!potentialOffsets.contains(temp - c))
						potentialOffsets.add(temp - c);
				}
			}
		}
	}

	/**
	 * Prints out the values which represent the frequencies of each character
	 * found in the cipher.
	 */
	private static void printFrequencies() {
		// get handle to an iterator of map Entries.
		Iterator<Entry<Character, Integer>> it = frequencies.entrySet()
				.iterator();

		// allocate memory for temporary storage of the Entries.
		Entry<Character, Integer> val;

		// as long as there is an other, get a reference to it and print out its
		// key and value.
		while (it.hasNext()) {
			val = it.next();
			System.out.println(val.getKey() + ": " + val.getValue());
		}
	}

	private static void printPotentialOffsets() {
		for (int offset : potentialOffsets) {
			System.out.println(offset);
		}
	}
	
	private static void printPotentialPlaintexts(){
		for(int offset : potentialOffsets){
			for(int i = 0; i < cipher.length(); i++){
				if(cipher.charAt(i) != ' ')
					System.out.print((char) (cipher.charAt(i) - offset));
				else
					System.out.print(' ');
			}
			System.out.print("\n");
		}
	}
}