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

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class BlockCipherSample {

	public static void run() {
		testFixedKeyAndIv();
		// testFixedKeyAndRandomIv();
		testAesGcm();
	}

	public static void testFixedKeyAndIv() {
		byte[] message = "A quick brown fox jumps over the lazy dog.".getBytes();
		byte[] key = "0123456789abcdef".getBytes();
		byte[] iv = "fedcba9876543210".getBytes();

		PrintHelper.print_title("Encryptions and decryptions using fixed key and iv");
		testModeOfOperation(message, key, null, "AES", "ECB", "PKCS5Padding");
		testModeOfOperation(message, key, iv, "AES", "CBC", "PKCS5Padding");
		testModeOfOperation(message, key, iv, "AES", "CFB", "nopadding");
		testModeOfOperation(message, key, iv, "AES", "OfB", "NoPadding");
		testModeOfOperation(message, key, iv, "AES", "CTR", "NOPADDING");
		System.out.println();
	}

	public static void testFixedKeyAndRandomIv() {
		byte[] message = "A quick brown fox jumps over the lazy dog.".getBytes();
		byte[] key = new byte[16];
		byte[] iv = new byte[16];

		PrintHelper.print_title("Encryptions and decryptions using fixed key and random iv");

		SecureRandom rand = new SecureRandom();
		rand.nextBytes(key);

		testModeOfOperation(message, key, null, "AES", "ECB", "PKCS5Padding");

		rand.nextBytes(iv);
		testModeOfOperation(message, key, iv, "AES", "CBC", "PKCS5Padding");

		rand.nextBytes(iv);
		testModeOfOperation(message, key, iv, "AES", "CFB", "nopadding");

		rand.nextBytes(iv);
		testModeOfOperation(message, key, iv, "AES", "OFB", "NoPadding");

		rand.nextBytes(iv);
		testModeOfOperation(message, key, iv, "AES", "CTR", "NOPADDING");
	}

	public static void testAesGcm() {
		byte[] msg = "A quick brown fox jumps over the lazy dog.".getBytes();
		byte[] key = "0123456789abcdef".getBytes();
		byte[] iv = "fedcba9876543210".getBytes();
		byte[] aad = "additional authenticated data".getBytes();
		String algorithm = "AES";
		String transformation = algorithm + "/GCM/NoPadding";

		PrintHelper.print_title("Test AES GCM");
		byte[] enc = BlockCipherSample.encryptGcm(msg, key, iv, aad, algorithm, transformation);
		byte[] dec = BlockCipherSample.decryptGcm(enc, key, iv, aad, algorithm, transformation);

		System.out.println("   ENC: " + DatatypeConverter.printHexBinary(enc));
		System.out.println("   DEC: " + new String(dec));
		System.out.println();
	}

	public static void testModeOfOperation(byte[] msg, byte[] key, byte[] iv, String algorithm, String mode,
			String padding) {
		String transformation = algorithm + "/" + mode + "/" + padding;

		byte[] enc = null;
		byte[] dec = null;

		if (iv == null) {
			enc = encrypt(msg, key, algorithm, transformation);
			dec = decrypt(enc, key, algorithm, transformation);
		} else {
			enc = encrypt(msg, key, iv, algorithm, transformation);
			dec = decrypt(enc, key, iv, algorithm, transformation);
		}

		System.out.println("   " + mode + "_ENC: " + DatatypeConverter.printHexBinary(enc));
		System.out.println("   " + mode + "_DEC: " + new String(dec));
		System.out.println();
	}

	public static byte[] encrypt(byte[] message, byte[] key, String algorithm, String transformation) {

		byte[] encrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, algorithm);

			Cipher cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			encrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encrypted;
	}

	public static byte[] decrypt(byte[] message, byte[] key, String algorithm, String transformation) {

		byte[] decrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, algorithm);

			Cipher cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
			decrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return decrypted;
	}

	public static byte[] encrypt(byte[] message, byte[] key, byte[] iv, String algorithm, String transformation) {

		byte[] encrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, algorithm);
			IvParameterSpec ivParam = new IvParameterSpec(iv);

			Cipher cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParam);
			encrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encrypted;
	}

	public static byte[] decrypt(byte[] message, byte[] key, byte[] iv, String algorithm, String transformation) {

		byte[] decrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, algorithm);
			IvParameterSpec ivParam = new IvParameterSpec(iv);

			Cipher cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParam);
			decrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return decrypted;
	}

	public static byte[] encryptGcm(byte[] message, byte[] key, byte[] iv, byte[] aad, String algorithm,
			String transformation) {
		byte[] encrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, algorithm);
			GCMParameterSpec spec = new GCMParameterSpec(128, iv);

			Cipher cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
			cipher.updateAAD(aad);
			encrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encrypted;
	}

	public static byte[] decryptGcm(byte[] message, byte[] key, byte[] iv, byte[] aad, String algorithm,
			String transformation) {
		byte[] decrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, algorithm);
			GCMParameterSpec spec = new GCMParameterSpec(128, iv);

			Cipher cipher = Cipher.getInstance(transformation);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
			cipher.updateAAD(aad);
			decrypted = cipher.doFinal(message);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return decrypted;
	}

}
