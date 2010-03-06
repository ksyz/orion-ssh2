/*
 * PublicKeyDecoder.java
 *
 * Created on May 3, 2007, 2:28 PM
 *
 */

package com.trilead.ssh2.crypto;

import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 *
 * @author juraj
 */
public class PublicKeyDecoder {
	
	public PublicKeyDecoder() {
	}
	
	public static Object parseKey(char[] publicKeyData) throws IOException {
		BufferedReader br = new BufferedReader(new CharArrayReader(publicKeyData));
		
		Object key = null;
		String line = br.readLine();
		
		if (line == null)
			return null;
		
		line = line.trim();
		
		String[] arr = line.split(" ");
		
		if (arr.length >= 2) {
			if ((arr[0].compareTo("ssh-rsa") == 0) || (arr[0].compareTo("ssh-dss") == 0)) {
				// String keyname = arr[2];
				
				byte[] msg = Base64.decode(arr[1].toCharArray());
				
				if ("ssh-rsa".equals(arr[0])) {
					key = RSASHA1Verify.decodeSSHRSAPublicKey(msg);
				} else if ("ssh-dss".equals(arr[0])) {
					key = DSASHA1Verify.decodeSSHDSAPublicKey(msg);
				}
			}
		}
		return key;
	}
	
	public static Object parseKey(File publicKey) throws IOException {
		char[] buff = new char[512];
		
		CharArrayWriter cw = new CharArrayWriter();
		
		publicKey.createNewFile();
		
		FileReader fr = new FileReader(publicKey);
		
		while (true) {
			int len = fr.read(buff);
			if (len < 0)
				break;
			cw.write(buff, 0, len);
		}
		
		fr.close();
		
		return parseKey(cw.toCharArray());
	}
	
}