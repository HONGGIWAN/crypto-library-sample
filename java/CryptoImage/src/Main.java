import java.awt.image.BufferedImage;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import lecture.crypto.image.BufferedImageCipher;
import lecture.crypto.image.ImageViewer;

public class Main {

	public static Cipher getAesEcbEncryptCipher(byte[] key) {
		Cipher cipher = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, "AES");

			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return cipher;

	}

	public static void showEcbIsNotSecure() {
		try {
			byte[] key = "0123456789abcdef".getBytes();

			Cipher cipher = getAesEcbEncryptCipher(key);
			BufferedImage img = BufferedImageCipher.open("linux-penguin.png");
			BufferedImage enc = BufferedImageCipher.encrypt(img, cipher);

			new ImageViewer("Original Image", img).setVisible(true);
			new ImageViewer("Encrypted Image", enc).setVisible(true);
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}
	
	public static void showNonceReuseExample() {
		try {
			byte[] key = "0123456789abcdef".getBytes();

			Cipher cipher = getAesEcbEncryptCipher(key);
			BufferedImage map1 = BufferedImageCipher.open("map1.png");
			BufferedImage map2 = BufferedImageCipher.open("map2.png");
			BufferedImage enc1 = BufferedImageCipher.encrypt(map1, cipher);
			BufferedImage enc2 = BufferedImageCipher.encrypt(map2, cipher);
			BufferedImage diff = BufferedImageCipher.diff(enc1, enc2);

			new ImageViewer("Empty Map", map1).setVisible(true);
			new ImageViewer("Pinned Map", map2).setVisible(true);
			new ImageViewer("Encrypted 1", enc1).setVisible(true);
			new ImageViewer("Encrypted 2", enc2).setVisible(true);
			new ImageViewer("Difference Image", diff).setVisible(true);
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}

	public static void main(String[] args) {
		//showEcbIsNotSecure();
		showNonceReuseExample();
	}

}
