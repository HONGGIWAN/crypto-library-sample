/**
 * MIT License
 * 
 * Copyright (c) 2018 Ilwoong Jeong, https://github.com/ilwoong
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package lecture.crypto.sample;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class PublicKeyCryptoSample {

	public static void run() {
		KeyPair pair = generateKeyPair();
		PublicKey pubKey = pair.getPublic();
		PrivateKey priKey = pair.getPrivate();
		
		String algorithm = "SHA256withRSA";

		byte[] message = "A quick brown fox jumps over the lazy dog.".getBytes();
		byte[] encrypted = encrypt(pubKey, message);
		byte[] decrypted = decrypt(priKey, encrypted);
		byte[] sig = DigitalSignature.sign(message, priKey, algorithm);
		boolean verified = DigitalSignature.verify(message, sig, pubKey, algorithm);

		PrintHelper.print_title("RSA encryption / signature");
		PrintHelper.print_hex("RSA Public Key", pubKey.getEncoded());
		PrintHelper.print_hex("RSA Private Key", priKey.getEncoded());
		PrintHelper.print_hex("Plain Text", message);
		PrintHelper.print_hex("RSA encryption", encrypted);
		PrintHelper.print_hex("RSA decryption", decrypted);
		PrintHelper.print_hex("RSA signature", sig);
		System.out.println("RSA signature verification: " + verified);
	}

	public static KeyPair generateKeyPair() {
		KeyPair pair = null;

		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			pair = gen.generateKeyPair();

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return pair;
	}

	public static byte[] encrypt(PublicKey key, byte[] message) {
		byte[] encrypted = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);

			encrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return encrypted;
	}

	public static byte[] decrypt(PrivateKey key, byte[] message) {
		byte[] decrypted = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);

			decrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return decrypted;
	}	

}
