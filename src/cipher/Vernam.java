/**
 * 
 */
package cipher;

import java.util.HashMap;

/**
 * @author George Lambadas 7077076
 * 
 */
public class Vernam {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// build alphabet of characters and binary encodings
		HashMap<Character, String> alphabet = new HashMap<Character, String>();
		alphabet.put('A', "000");
		alphabet.put('E', "001");
		alphabet.put('I', "010");
		alphabet.put('M', "011");
		alphabet.put('O', "100");
		alphabet.put('R', "101");
		alphabet.put('T', "110");
		alphabet.put('V', "111");

		partA(alphabet);
		
		partB(alphabet);
	}

	/**
	 * @param alphabet
	 */
	private static void partB(HashMap<Character, String> alphabet) {

		String c1 = "IEEIA", c2 = "ORVRO";
		String m11 = "R", m24 = "T";
		System.out.println(c1.charAt(0)+"");
		System.out.println("Key starting bits: " + xor(translateMessageToBits(m11, alphabet), translateMessageToBits(c1.charAt(0)+"", alphabet)));
		System.out.println("Key 4th set of bits: " + xor(translateMessageToBits(m24, alphabet), translateMessageToBits(c2.charAt(3)+"", alphabet)));
	}

	public static void partA(HashMap<Character, String> alphabet) {
		// specify message and cyphertext
		String message = "MARIO";
		String cypherMessage = "AOAMV";

		System.out.println("Plain text message: " + message);
		System.out.println("Cyphertext message: " + cypherMessage);
		// create bit sequences for the message and the cyphertext via the
		// aplphabet
		String messageBits = translateMessageToBits(message, alphabet), cypherBits = translateMessageToBits(
				cypherMessage, alphabet);

		System.out.println("Plain text binary: " + messageBits);
		System.out.println("Cyphertext binary: " + cypherBits);

		System.out.print("Result of plain text XOR cyphertext: ");

		// print the key used to convert the message bits to the cyphertext bits
		System.out.println(xor(messageBits, cypherBits));
	}

	public static String translateMessageToBits(String message,
			HashMap<Character, String> alphabet) {
		String messageBits = "";
		for (int i = 0; i < message.length(); i++) {
			messageBits += alphabet.get(message.charAt(i));
		}
		return messageBits;
	}

	public static String xor(String first, String second) {
		String returnString = null;

		if (first.length() == second.length()) {
			char firstChar, secondChar;
			returnString = "";
			for (int i = 0; i < first.length(); i++) {

				firstChar = first.charAt(i);
				secondChar = second.charAt(i);

				returnString += firstChar == secondChar ? "0" : "1";
			}
		}
		return returnString;
	}

}
