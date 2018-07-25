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

public class PrintHelper {
	private static final String TAB = "    ";

	public static void print_title(String title) {
		System.out.println("********************************************************************************");
		System.out.println("* " + title);
		System.out.println("********************************************************************************");
	}

	public static void print_hex(String title, byte[] data) {
		System.out.printf("%s[%d bytes]\n", title, data == null ? 0 : data.length);
		System.out.print(TAB);

		if (data == null) {
			System.out.println("null");
			return;
		}

		for (int i = 0; i < data.length; ++i) {
			System.out.printf("%02x", data[i]);

			if (((i + 1) & 0x1f) == 0 && ((i + 1) != data.length)) {
				System.out.println();
				System.out.print(TAB);
			} else if (((i + 1) & 0x3) == 0) {
				System.out.print(" ");
			}
		}

		System.out.println();
	}
}
