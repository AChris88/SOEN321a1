package cipher;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

public class AES256 {

	// Question 1.3a
	// Pu before being converted to Cu
	private static String unauthenticatedCookie = "user=anonymous,tmstmp=1443657660";
	// Pa before being converted to Ca
	private static String authenticatedCookie = "user=admin,tmstmp=1443657660";
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
		 		byte[] message = "hello world".getBytes(StandardCharsets.UTF_8);
				String encoded = Base64.getEncoder().encodeToString(message);
				byte[] decoded = Base64.getDecoder().decode(encoded);
		
				System.out.println(encoded);
				System.out.println(new String(decoded, StandardCharsets.UTF_8));
				
		 */
		
		byte[] tmp1 = cipher.getBytes(StandardCharsets.UTF_8);
		byte[] tmp2 = plaintextAnonCookie.getBytes(StandardCharsets.UTF_8);

		System.out.println(new String(tmp1));
		
		System.out.println("tmp1: " + tmp1.length + " tmp2: " + tmp2.length);
		for (int i = 0; i < tmp2.length; i++) {
			tmp1[i] = (byte) (tmp1[i] ^ tmp2[i]);
		}

		String output = new String(tmp1, StandardCharsets.UTF_8);

		System.out.println(output);
	}
}