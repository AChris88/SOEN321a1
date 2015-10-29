package cipher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

/**
 * Class used to break the Caesar cipher and to extract the hidden message.
 * 
 * @author Christian Allard 27026188
 * @created 10/10/2015
 * @edited 16/10/2015
 */

public class Caesar {

	// Pre-defined assignment values
	private static String cipher = "KNXMN SLKWJ XMBFY JWGJS IXFSI FIRNY XBTWI KNXMW FSPTA JWBMJ QRNSL FSDIF D";
	private static char[] mostUsed = { 'E', 'T', 'A', 'O', 'I', 'N' };

	// Variables used for data storage and manipulation
	private static String plainText = "";
	private static HashMap<Character, Integer> frequencies = new HashMap<Character, Integer>();
	private static ArrayList<Integer> potentialOffsets = new ArrayList<Integer>();

	public static void main(String[] args) {
		// frequency analysis of characters on ciphertext
		getCharCount();
		// determine most likely offsets given ciphertext character frequencies
		setPotentialOffsets();

		System.out.println("These are the potential plaintext values:");
		// print the potential plaintext values given the known most likely
		// offsets
		printPotentialPlaintexts();

		System.out
				.println("The only one of these that is readable is the 6th, (same as the 9th).");

		// after observing the output of printPotentialPlaintexts,
		// the following plaintext message was obtained using the offsets
		// of -8 and 18
		plainText = "FISHING FRESHWATER BENDS AND ADMIT SWORDFISH RANK OVERWHELMING ANYDAY";

		System.out.println(plainText);

		System.out
				.println("The hidden message in the third character of each word is:");
		printHiddenMessage();
	}

	/**
	 * 
	 * 
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
	 */
	private static void setPotentialOffsets() {
		int highestCount = 0;

		Iterator<Entry<Character, Integer>> it = frequencies.entrySet()
				.iterator();
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
	 * Prints out the hidden message in the decrypted cipher.
	 */
	private static void printHiddenMessage() {
		// converts the decrypted message into an array of individual words
		String[] words = plainText.split(" ");

		// iterates through every word and if it is at least 3 characters,
		// prints out the third character.
		for (String word : words) {
			if (word.length() >= 3)
				System.out.print(word.charAt(2));
		}
	}

	// Helper methods used to see obtained values for character frequencies,
	// potential offsets, and potential plaintext values.

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

	/**
	 * Prints out the potential offsets of the Caesar cipher.
	 */
	private static void printPotentialOffsets() {
		for (int offset : potentialOffsets) {
			System.out.println(offset);
		}
	}

	/**
	 * Prints out the potential plaintext values after decrypting the Caesar
	 * cipher.
	 */
	private static void printPotentialPlaintexts() {
		// iterate through the potential offsets
		for (int j = 0; j < potentialOffsets.size(); ++j) {
			int offset = potentialOffsets.get(j);
			System.out.print((j + 1) + " - ");
			// iterate through every character in the cipher
			for (int i = 0; i < cipher.length(); i++) {
				// unless the character is a space, print out the character
				// after having applied the current offset
				if (cipher.charAt(i) != ' ')
					System.out
							.print((char) (((cipher.charAt(i) - offset) % 26) + 65));
				else
					System.out.print(' ');
			}
			System.out.print("\n");
		}
	}
}