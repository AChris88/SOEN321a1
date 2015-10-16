package stats;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class WebSecStats {

	public static void main(String[] args) {
		// Set the starting point of the ranger of websites to analyze
		int[] ranges = { getStartIndex(27026188), getStartIndex(27077076) };
		// Top million site listing
		String path = "Oct_13_2015_top-1m.csv";
		// Goes through the listing and analyzes all sites in the accepted
		// range.
		// analyzeSiteListing(path, ranges);
		analyzeSite(1, "live.com");
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

	/**
	 * Creates an SSLSocket connection to the specified domain and retrieves
	 * information regarding the security of the connections it establishes with
	 * its users.
	 * 
	 * @param rank
	 *            is the ranking of the domain as of October 13, 2015
	 * @param domain
	 *            is the website to be analyzed
	 */
	private static void analyzeSite(int rank, String domain) {
		// Setting accepted connection protocols
		System.setProperty("https.protocols", "SSLv3,TLSv1,TLSv1.1,TLSv1.2");

		// Instantiating variables required for socket connections
		SSLSocketFactory factory = null;
		Socket socket = null;
		SSLSession session = null;
		Certificate[] certificates = null;

		// Instantiating variables used to store retrieved data
		String protocol = "";
		String cipherSuite = "";
		String host = domain;
		String keyType = "";
		String keySize = "";
		String algorithm = "";

		// Instantiating booleans used to verify connection states
		boolean isHTTPS = true;
		boolean isHSTS = true;
		boolean isHSTSLong = true;
		boolean hostFound = true;
		boolean connectionError = false;

		// Variable to contain final site analysis
		String analysis = "";

		try {
			// Get instance of an SSLSocketFactory
			factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			// Create socket connection to the specified domain using port 443
			socket = factory.createSocket(domain, 443);
			// Get handle to the session object from the socket connection
			session = ((SSLSocket) socket).getSession();

			/*
			 * certificates = session.getPeerCertificates();
			 * System.out.println("Certificates:"); for (int i = 0; i <
			 * certificates.length; i++) { System.out.println(((X509Certificate)
			 * certificates[i]).getSubjectDN()); }
			 * System.out.println("Peer host is " + session.getPeerHost());
			 * System.out.println("Cipher is " + session.getCipherSuite());
			 * System.out.println("Protocol is " + session.getProtocol());
			 * System.out.println("Session: " + session);
			 */

			// If the session is not null, begin extracting socket connection
			// information
			if (session != null) {
				// Identify host, protocol, and cipher suite
				host = session.getPeerHost();
				protocol = session.getProtocol();
				cipherSuite = session.getCipherSuite();

				// Identify encryption algorithm
				algorithm = cipherSuite
						.substring(cipherSuite.lastIndexOf('_') + 1);

				// Sets flag stating if the site uses HTTPS
				if (protocol.equals("SSL") || protocol.equals("TLSv1")
						|| protocol.equals("TLSv1.1")
						|| protocol.equals("TLSv1.2"))
					isHTTPS = true;

				// Identify key type used
				if (cipherSuite.contains("ECDHE"))
					keyType = "ECDHE";
				else if (cipherSuite.contains("ECDSA"))
					keyType = "ECDSA";
				else if (cipherSuite.contains("_RSA_"))
					keyType = "RSA";

				// Identify key size used
				if (cipherSuite.contains("AES_")
						&& cipherSuite.contains("_GCM_"))
					keySize = cipherSuite.substring(
							cipherSuite.indexOf("AES_") + 4,
							cipherSuite.indexOf("_GCM_"));
			}
		} catch (UnknownHostException e) {
			// 404 response code
			hostFound = false;
		} catch (ConnectException e) {
			if (e.getMessage().contains("Connection refused")) {
				// cannot connect due to set protocols only accepting SSL/TLS
				isHSTS = false;
			} else {
				connectionError = true;
			}
		} catch (Exception e) {
			// Any other exception encountered.
			e.printStackTrace();
		} finally {
			// Creating the comma-delimited analysis report
			String errorMessage = "";
			if (connectionError) {
				// A connection error occurred
				errorMessage = "connection error";
				analysis = rank + "," + host + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + "\n";
			} else if (!hostFound) {
				// The requested domain was not found
				errorMessage = "404 response code";
				analysis = rank + "," + host + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + "\n";
			} else if (!isHSTS) {
				// The requested domain does not support HSTS
				isHSTSLong = false;
				isHTTPS = false;
				analysis = rank + "," + host + "," + isHTTPS + ",,,,," + isHSTS
						+ "," + isHSTSLong + "\n";
			} else {
				// No errors were encountered in analyzing the requested domain
				analysis = rank + "," + host + "," + isHTTPS + "," + protocol
						+ "," + keyType + "," + keySize + "," + algorithm + ","
						+ isHSTS + "," + isHSTSLong + "\n";
			}
			// Send anaysis off to be written to a CSV file
			recordAnalysis(analysis);
			try {
				// Close the socket connection if it is not null
				if (socket != null)
					socket.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Opens and iterates through a CSV file line-by-line in order for each
	 * entry to be analyzed.
	 * 
	 * @param path
	 *            indicates the CSV file to be accessed.
	 * @param ranges
	 *            indicates the starting point of the ranges of surplus websites
	 *            to analyze.
	 */
	private static void analyzeSiteListing(String path, int[] ranges) {
		// Set start and end of the first range
		int startRange1 = ranges[0];
		int endRange1 = startRange1 + 10000;

		// Set start and end of the second range
		int startRange2 = ranges[1];
		int endRange2 = startRange2 + 10000;

		// Instantiate the variables needed to handle the CSV file
		BufferedReader br = null;
		FileReader fr = null;
		String line = null;

		// Instantiate the variables needed to hold the ranking and domain of
		// each website in the CSV file
		int recordNum = 0;
		String url = "";

		try {
			// Create new file reader usng the path of the CSV file
			fr = new FileReader(path);
			// Create new buffered reader using the file reader that was just
			// created
			br = new BufferedReader(fr);

			// As long as the file has more lines, assign them to the line
			// variable
			while ((line = br.readLine()) != null) {
				// Get the assigned record number.
				recordNum = Integer.parseInt(line.substring(0,
						line.indexOf(',')));
				// Get the website domain to analyze
				url = line.substring(line.indexOf(',') + 1);
				// If the record number falls within the accepted ranges, then
				// the website it analyzed.
				if (recordNum <= 1000
						|| (recordNum >= startRange1 && recordNum < endRange1)
						|| (recordNum >= startRange2 && recordNum < endRange2)) {
					analyzeSite(recordNum, url);
				} else if (recordNum >= endRange2) {
					// If the record number exceeds the end of the second range,
					// we stop iterating through the file.
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				// Close the buffered reader
				if (br != null)
					br.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Appends the sent in analysis string to a CSV file.
	 * 
	 * @param analysis
	 *            string which contains information about the analyzed website.
	 */
	private static void recordAnalysis(String analysis) {
		try {
			Files.write(Paths.get("analysis.csv"), analysis.getBytes(),
					StandardOpenOption.APPEND);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}