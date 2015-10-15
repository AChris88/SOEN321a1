package cipher;

import java.io.UnsupportedEncodingException;

import javax.xml.bind.DatatypeConverter;


public class AES256 {

	//Question 1.3a
	//Pu before being converted to Cu
	private static String unauthenticatedCookie = "user=anonymous,tmstmp=1443657660";
	//Pa before being converted to Ca
	private static String authenticatedCookie = "user=admin,tmstmp=1443657660";
	//The difference observed is that the string length is clearly 4 characters shorter.
	//However, once encrypted, it will still result in a 256 bit cipher.

	private static String base64Cipher = "40mO35Yj9cAMFaaOcshT10VwVw6WmbvAEyrI6TxElFY=";
	
	public static void main(String[] args){
		base64Decrypt(base64Cipher);
	}
	
	private static void base64Decrypt(String cipher){
		byte[] tmp1 = cipher.getBytes();
		byte[] tmp2 = DatatypeConverter.parseBase64Binary(cipher);

		System.out.println(cipher);
		
		for(int i = 0 ; i < tmp2.length ; i++){
			tmp1[i] = (byte) (tmp1[i] ^ tmp2[i]);
		}
		
		String output = new String(tmp1);
		
		System.out.println(output);
	}
}