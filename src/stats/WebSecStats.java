package stats;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class WebSecStats {

	public static void main(String[] args) {
		int[] ranges = {getStartIndex(27026188), getStartIndex(27077076)};
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
		return bi.mod(new BigInteger("9890")).multiply(new BigInteger("100"))
				.intValue() + 1000;
	}

	private void analyzeSites(String path, int[] ranges) {
		///
		path = "Oct_13_2015_top-1m.csv";
		///
		BufferedReader br = null;
		FileReader fr = null;
		List<String> lines = new ArrayList<String>();
		String line = null;
		try {
			fr = new FileReader(path);
			br = new BufferedReader(fr);
			while ((line = br.readLine()) != null) {
				lines.add(line);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	private void recordAnalysis(String analysis) {
		try {
			Files.write(Paths.get("analysis.csv"), analysis.getBytes(),
					StandardOpenOption.APPEND);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}