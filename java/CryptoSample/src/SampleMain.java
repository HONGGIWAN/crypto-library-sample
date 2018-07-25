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

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

import lecture.crypto.sample.BlockCipherSample;
import lecture.crypto.sample.DigitalSignature;
import lecture.crypto.sample.HashSample;
import lecture.crypto.sample.MacSample;
import lecture.crypto.sample.PublicKeyCryptoSample;

public class SampleMain {

	public static void listProviders(String type) {
		for (Provider provider : Security.getProviders()) {
			for (Service service : provider.getServices()) {
				if (type.toLowerCase().equals("all") || type.equals(service.getType())) {
					System.out.println(service.getType() + " / " + service.getAlgorithm());
				}
			}
		}
	}

	public static void main(String[] args) {
		BlockCipherSample.run();
		HashSample.run();
		MacSample.run();
		PublicKeyCryptoSample.run();
	}
}
