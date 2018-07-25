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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DigitalSignature {

	public static byte[] sign(byte[] msg, PrivateKey key, String algorithm) {
		byte[] signature = null;

		try {
			Signature signer = Signature.getInstance(algorithm);
			signer.initSign(key);
			signer.update(msg);
			signature = signer.sign();

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return signature;
	}

	public static boolean verify(byte[] msg, byte[] signature, PublicKey key, String algorithm) {
		boolean isVerified = false;

		try {
			Signature verifier = Signature.getInstance(algorithm);
			verifier.initVerify(key);
			verifier.update(msg);
			isVerified = verifier.verify(signature);

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return isVerified;
	}

}
