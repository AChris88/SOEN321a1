package cipher;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

public class AES256 {

	// Question 1.3a
	// Pu before being converted to Cu
	private static String unauthenticatedCookie = "user=anonymous,tmstmp=";
	// Pa before being converted to Ca
	private static String authenticatedCookie = "user=admin,tmstmp=0000";
	// The difference observed is that the string length is clearly 4 characters
	// shorter.
	// However, as a result, this may change the length of the generated
	// cipher.

	private static String plaintextAnonCookie = "user=anonymous,tmstmp=1443657660";
	private static String base64Cipher = "40mO35Yj9cAMFaaOcshT10VwVw6WmbvAEyrI6TxElFY=";

	public static void main(String[] args) {
		base64Decrypt(base64Cipher);
	}

	private static void base64Decrypt(String cipher) {
		/*
		 * byte[] message = "hello world".getBytes(StandardCharsets.UTF_8);
		 * String encoded = Base64.getEncoder().encodeToString(message); byte[]
		 * decoded = Base64.getDecoder().decode(encoded);
		 * 
		 * System.out.println(encoded); System.out.println(new String(decoded,
		 * StandardCharsets.UTF_8));
		 */

		byte[] tmp1 = cipher.getBytes(StandardCharsets.UTF_8);
		byte[] tmp2 = unauthenticatedCookie.getBytes(StandardCharsets.UTF_8);
		byte[] adminCookie = authenticatedCookie
				.getBytes(StandardCharsets.UTF_8);
		byte[] outputOf14Steps = new byte[cipher.length()];
		byte[] finalEncryptedCookie = new byte[cipher.length()];

		// go to length of unauthenticated cookie XORing with ciphertext in
		// order to get the output of the block ciphers
		for (int i = 0; i < tmp2.length; i++) {
			outputOf14Steps[i] = (byte) (tmp1[i] ^ tmp2[i]);
		}
		
		//take the padded admin cookie and encrypt it using XOR with the output of the previous step
		int i;
		for (i = 0; i < tmp2.length; i++) {
			finalEncryptedCookie[i] = (byte) (adminCookie[i] ^ outputOf14Steps[i]);
		}

		//copy the remainder of the old encrypted cookie into the new cookie
		//this portion is the timestamp value which is unknown
		for (; i < tmp1.length; i++) {
			finalEncryptedCookie[i] = tmp1[i];
		}

		System.out.println(new String(finalEncryptedCookie,
				StandardCharsets.UTF_8));

	}
}