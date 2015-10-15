package stats;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class WebSecStats {

	public static void main(String[] args) {
		getStartIndex(27026188);
		getStartIndex(27077076);
	}

	private static int getStartIndex(int studentId) {
		MessageDigest md = null;

		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		md.update(new Integer(studentId).toString().getBytes());
		BigInteger bi = new BigInteger(1, md.digest());
		return bi.mod(new BigInteger("9890"))
				.multiply(new BigInteger("100")).intValue() + 1000;
	}
}
