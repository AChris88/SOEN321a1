package cipher;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This is a class used to programatically solve 1.3 C of Assignment 1. An
 * AES256 cookie encrypted with OFB must be altered without knowing k or IV. The
 * original cookie as well as the original ciphertext are known.
 * 
 * @author George Lambadas 27077076
 * @author Christian Allard 27026188
 * @created 10/10/2015
 * @edited 16/10/2015
 * 
 */
public class AES256 {

	// Pu before being converted to Cu
	private static String plaintextAnonCookie = "user=anonymous,tmstmp=1443657660";
	// Pa before being converted to Ca
	private static String authenticatedCookie = "user=admin,tmstmp=00001443657660";
	// Cu generated from the above Pu
	private static String base64Cipher = "40mO35Yj9cAMFaaOcshT10VwVw6WmbvAEyrI6TxElFY=";

	/**
	 * Driver method for editing the cookie.
	 * 
	 * @param args
	 *            command line arguments. Not used.
	 */
	public static void main(String[] args) {
		alterCookie(base64Cipher, plaintextAnonCookie, authenticatedCookie);
	}

	/**
	 * This method accepts as input an authenticated, encryted cookie, the
	 * original plaintext cookie and a new cookie. It will reverse the
	 * encryption process in order to recreate it with a new cookie. Output is
	 * the possible options for a new cookie based upon where a smaller cookie
	 * may be padded.
	 * 
	 * @param cipherCookie
	 *            base64-encoded unauthenticated cookie ciphertext
	 * @param plainTextOriginalCookie
	 *            plain text unauthenticated cookie
	 * @param plainTextNewCookie
	 *            plain text authenticated cookie
	 */
	private static void alterCookie(String cipherCookie,
			String plainTextOriginalCookie, String plainTextNewCookie) {
		byte[] cipher = Base64.getDecoder().decode(cipherCookie);
		byte[] originalBytes = plainTextOriginalCookie.getBytes();
		byte[] newBytes = plainTextNewCookie.getBytes();
		byte[] newCipherBytes = new byte[newBytes.length];

		System.out.println("original: " + base64Cipher);
		for (int j = 0; j < originalBytes.length - newBytes.length; j++) {
			for (int i = 0; i < newBytes.length; i++) {
				newCipherBytes[i] = (byte) ((originalBytes[i + j] ^ cipher[i
						+ j]) ^ newBytes[i]);
			}
			System.out.println("option#" + (j + 1) + ": "
					+ new String(Base64.getEncoder().encode(newCipherBytes)));
		}
	}
}
