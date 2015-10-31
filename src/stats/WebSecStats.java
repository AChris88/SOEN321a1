package stats;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Class used to analyze the security of connections established to 21,000 out
 * of the top million sites in the world.
 * 
 * @author Christian Allard 27026188
 * 
 * @created 15/10/2015
 * @edited 30/10/2015
 *
 */

public class WebSecStats {

	// Instantiating variables required for socket connections
	private static SSLSocketFactory factory = null;
	private static Socket socket = null;
	private static SSLSession session = null;
	private static Certificate[] certificates = null;

	// Instantiating variables used to store retrieved data
	private static String protocol = "";
	private static String host = "";
	private static String keyType = "";
	private static String keySize = "";
	private static String algorithm = "";
	private static String pubKey = "";
	private static String sigAlgo = "";
	private static String httpHeader = "";
	private static String httpTmp = "";
	private static String flag = "";
	private static String analysis = "";

	// Instantiating booleans used to verify connection states
	private static boolean isHTTPS = true;
	private static boolean isHSTS = false;
	private static boolean isHSTSLong = false;
	private static boolean hostFound = true;
	private static boolean connectionError = false;


	
	public static void main(String[] args) {
		// Top million site listing
		String path = "Oct_13_2015_top-1m.csv";
		
		// Pulls the listing and analyzes all sites in the accepted range.
		int startRange = getStartIndex(27026188);
		int endRange = getStartIndex(27077076);
		
		analyzeSiteListing(path, startRange, endRange);
		
		/* TESTING */
//		System.out.println("Start: " + startRange + ", End: " + endRange);
//		analyzeSite(1, "facebook.com");
//		System.out.println("HTTPHeader:\n" + getHTTPHeader("https://facebook.com"));
	}

	/**
	 * Utility method used to obtain the number of the starting record of a 10,000 block
	 * of domains to analyze. 
	 * 
	 * @param studentId used to generate an integer which indicates the record number
	 * 					which is the start of a 10,000 domain block to analyze. 
	 * @return integer value which indicates the start of the range of domains to analyze.
	 */
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
		
		// Setting booleans used to verify connection states
		isHTTPS = true;
		isHSTS = false;
		isHSTSLong = false;
		hostFound = true;
		connectionError = false;

		try {
			// Get instance of an SSLSocketFactory
			factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			// Create socket connection to the specified domain using port 443
			socket = factory.createSocket(domain, 443);
			// Get handle to the session object from the socket connection
			session = ((SSLSocket) socket).getSession();
			
			// If the session is not null, begin extracting socket connection information
			if (session != null) {
				
				// Retrieve HTTP header from the domain
				httpHeader = getHTTPHeader("https://"+domain);

				// Determines if the domain enforces HSTS
				if(httpHeader.contains("Strict-Transport-Security")){
					// Extracting HSTS parameters
					httpTmp = httpHeader.substring(httpHeader.indexOf("Strict-Transport-Security"));

					// Establishing HSTS as being supported
					isHSTS = true;
					
					// Assigning flag to find duration of HSTS
					flag = "max-age=";
					
					// Determines the max-age of HSTS
					if (httpTmp.contains(flag)){
						
						// Getting a handle to HSTS configuration list, where max-age value is the first value
						httpTmp = httpTmp.substring(httpTmp.indexOf(flag) + flag.length(), httpTmp.indexOf(']'));
						
						// If there are multiple configuration values, extract only the HSTS max-age
						if(httpTmp.contains(";")) {
							httpTmp = httpTmp.substring(0, httpTmp.indexOf(';'));
						}
						
						// Parse max-age value to be numerically compared
						long maxAge = Long.parseLong(httpTmp);
						
						// If HSTS max-age is greater than a month, then HSTSLong is true
						if(maxAge >= 2592000) {
							isHSTSLong = true;
						}
					}
				}
				
				
				/*
				 * session.getCertificates() occasionally throws
				 * "javax.net.ssl.SSLPeerUnverifiedException" exception
				 * which, according to Google, seems to be caused by out-dated certificates
				 */
				// Getting a handle to the first certificate provided by the domain 
				certificates = session.getPeerCertificates();
				X509Certificate certificate = (X509Certificate) certificates[0];
				
				// Getting the public key and signature algorithm from the certificate
				pubKey = certificate.getPublicKey().toString();
				sigAlgo = certificate.getSigAlgName();

				// Extracting the specific algorithm name
				algorithm = sigAlgo.substring(0, sigAlgo.indexOf("with"));
				
				// Extracting the exact key type and size
				keyType = pubKey.substring(pubKey.indexOf(' ') + 1, pubKey.indexOf(" public"));
				keySize = pubKey.substring(pubKey.indexOf(',') + 2, pubKey.indexOf(" bits"));
				
				// Identifying the host and protocol
				host = session.getPeerHost();
				protocol = session.getProtocol();
			}
		} catch (UnknownHostException e) {
			// 404 response code
			hostFound = false;
		} catch (ConnectException e) {
			if (e.getMessage().contains("Connection refused")) {
				// Cannot connect due to set protocols only accepting SSL/TLS
				isHTTPS = false;
			} else {
				// Other connection error occurred
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
			} else if (!hostFound) {
				// The requested domain was not found
				errorMessage = "404 response code";
			} 
			
			// If host is not found or there was a connection error,
			// display the error message in the domain analysis
			if (!hostFound || connectionError) {
				analysis = rank + "," + host + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + ","
						+ errorMessage + "," + errorMessage + "\n";
			} else {
				// No errors were encountered in analyzing the requested domain
				analysis = rank + "," + host + "," + isHTTPS + "," + protocol
						+ "," + keyType + "," + keySize + "," + algorithm + ","
						+ isHSTS + "," + isHSTSLong + "\n";
			}
			
			// Send analysis off to be written to a CSV file
			recordAnalysis(analysis);
			
			// Close the socket connection if it is not null
			if (socket != null)
				try {
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
	private static void analyzeSiteListing(String path, int range1, int range2) {
		// Set start and end of the first range
		int startRange1 = range1;
		int endRange1 = startRange1 + 10000;

		// Set start and end of the second range
		int startRange2 = range2;
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
			
			// Create new buffered reader using the file reader that was just created
			br = new BufferedReader(fr);

			// As long as the file has more lines, assign them to the line
			// variable
			while ((line = br.readLine()) != null) {
				// Get the assigned record number.
				recordNum = Integer.parseInt(line.substring(0,
						line.indexOf(',')));
				// Get the website domain to analyze
				url = line.substring(line.indexOf(',') + 1);
				// If the record number falls within the accepted ranges,
				// then the website it analyzed.
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
			// Close the buffered reader
			if (br != null){
				try {
					br.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Utility method used to obtain the HTTP header from the specified domain
	 * 
	 * @param domain for which to retrieve the HTTP header.
	 * @return String representation of the domain's HTTP header.
	 */
	private static String getHTTPHeader(String domain) {
		//Instantiate variables needed for processing of HTTP header
		URL url = null;
		URLConnection con = null;
		Map<String, List<String>> header = null;
		StringBuilder str = new StringBuilder();
		try {
			//Open connection to the domain
			url = new URL(domain);
			con = url.openConnection();
			
			//Retrieve connection HTTP header
			header = con.getHeaderFields();
			
			//Extract all header <key, value> pairs and append them to the StringBuilder
			for (Map.Entry<String, List<String>> entry : header.entrySet()) {
				str.append(entry.getKey() + " : " + entry.getValue() + "\n");
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		//Return the formatted HTTP header String 
		return str.toString();
	}

	/**
	 * Appends the sent in analysis string to a CSV file.
	 * 
	 * @param analysis
	 *            string which contains information about the analyzed website.
	 */
	private static void recordAnalysis(String analysis) {
		try {
			//Appends the analysis as an array of Bytes to the analysis.csv file
			Files.write(Paths.get("analysis.csv"), analysis.getBytes(),
					StandardOpenOption.APPEND);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}