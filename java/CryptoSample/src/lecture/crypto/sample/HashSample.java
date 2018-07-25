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

import java.security.MessageDigest;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HashSample {

	private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

	public static void run() {
		runDigest();
		runPbkdf2();
	}

	public static void runDigest() {
		byte[] msg = "A brown fox jumps over the lazy dog.".getBytes();

		byte[] md5 = digest(msg, "MD5");
		byte[] sha = digest(msg, "SHA");
		byte[] sha2 = digest(msg, "SHA-256");

		PrintHelper.print_title("Hash Functions");
		PrintHelper.print_hex("MD5", md5);
		PrintHelper.print_hex("SHA", sha);
		PrintHelper.print_hex("SHA-256", sha2);
		System.out.println();
	}

	public static void runPbkdf2() {
		String password = "A quick brown fox jumps over the lazy dog.";
		int iterations = 1000;
		byte[] salt = "sun-dried salt".getBytes();
		byte[] key = pbkdf2(password, salt, iterations, 16);

		PrintHelper.print_title("PBKDF2 / " + ALGORITHM);
		PrintHelper.print_hex("Password", password.getBytes());
		PrintHelper.print_hex("Salt", salt);
		System.out.println("Iterations: " + iterations);
		PrintHelper.print_hex("Key derived", key);
		System.out.println();
	}

	public static byte[] digest(byte[] msg, String algorithm) {
		byte[] digest = null;

		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(msg);
			digest = md.digest();

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return digest;
	}

	public static byte[] pbkdf2(String password, byte[] salt, int iterations, int bytes) {

		byte[] derived = null;

		try {
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, bytes * 8);
			SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);

			derived = skf.generateSecret(spec).getEncoded();
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return derived;
	}

}
