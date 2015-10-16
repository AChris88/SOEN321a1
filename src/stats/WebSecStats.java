package stats;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class WebSecStats {

	public static void main(String[] args) {
		int[] ranges = { getStartIndex(27026188), getStartIndex(27077076) };
		String path = "Oct_13_2015_top-1m.csv";
		// readSiteListing(path, ranges);
		analyzeSite(1, "google.com");
	}

	private static void analyzeSite(int rank, String domain) {
		// System.setProperty("javax.net.ssl.trustStore", "clienttrust");
		System.setProperty("https.protocols", "SSLv3,TLSv1,TLSv1.1,TLSv1.2");

		SSLSocketFactory factory = null;
		Socket socket = null;
		SSLSession session = null;
		Certificate[] certificates = null;

		String protocol = "";
		String cipherSuite = "";
		String host = "";
		String keyType = "";
		String keySize = "";
		String algorithm = "";
		
		boolean isHTTPS = false;
		boolean isHSTS = false;
		boolean isHSTSLong = false;
		
		String analysis = "";
		try {
			factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			socket = factory.createSocket(domain, 443);
			session = ((SSLSocket) socket).getSession();
			certificates = session.getPeerCertificates();

//			System.out.println("Certificates:");
//			for (int i = 0; i < certificates.length; i++) {
//				System.out.println(((X509Certificate) certificates[i])
//						.getSubjectDN());
//			}
//
//			System.out.println("Peer host is " + session.getPeerHost());
//			System.out.println("Cipher is " + session.getCipherSuite());
//			System.out.println("Protocol is " + session.getProtocol());
//			System.out.println("Session: " + session);
			
			host = session.getPeerHost();
			protocol = session.getProtocol();
			cipherSuite = session.getCipherSuite();
			
			algorithm = cipherSuite.substring(cipherSuite.lastIndexOf('_') + 1);
			
			if (protocol.equals("SSLv3") || protocol.equals("TLSv1")
					|| protocol.equals("TLSv1.1") || protocol.equals("TLSv1.2"))
				isHTTPS = true;

			if(cipherSuite.contains("ECDHE"))
				keyType = "ECDHE";
			else if(cipherSuite.contains("ECDSA"))
				keyType = "ECDSA";
			else if (cipherSuite.contains("_RSA_"))
				keyType = "RSA";
			
			keySize = cipherSuite.substring(cipherSuite.indexOf("AES_") + 4, cipherSuite.indexOf("_GCM_"));
			
			analysis = rank + "," + host + "," + isHTTPS + "," + protocol + "," + keyType + "," + keySize + "," + algorithm + "," + isHSTS + "," + isHSTSLong;
			
			System.out.println(analysis);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				socket.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
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

	private static void readSiteListing(String path, int[] ranges) {
		int startRange1 = ranges[0];
		int endRange1 = startRange1 + 10000;

		int startRange2 = ranges[1];
		int endRange2 = startRange2 + 10000;

		BufferedReader br = null;
		FileReader fr = null;
		String line = null;

		int recordNum = 1;
		String url = "";

		try {
			fr = new FileReader(path);
			br = new BufferedReader(fr);

			while ((line = br.readLine()) != null) {
				recordNum = Integer.parseInt(line.substring(0,
						line.indexOf(',')));
				url = line.substring(line.indexOf(','),
						line.indexOf(line.indexOf(','), line.indexOf(',') + 1));
				if (recordNum <= 1000
						|| (recordNum >= startRange1 && recordNum < endRange1)
						|| (recordNum >= startRange2 && recordNum < endRange2)) {
					analyzeSite(recordNum, url);
				} else if (recordNum >= endRange2) {
					break;
				}
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