package lecture.crypto.image;

import java.awt.Point;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.Raster;
import java.io.File;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

public class BufferedImageCipher {

	public static BufferedImage open(String path) {
		BufferedImage img = null;
		try {
			img = ImageIO.read(new File(path));
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return img;
	}

	public static void save(String path, BufferedImage img) {
		try {
			ImageIO.write(img, "png", new File(path));
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}
	
	public static BufferedImage encrypt(BufferedImage img, Cipher cipher) {
		BufferedImage encrypted = null;

		try {			
			DataBufferByte buffer = (DataBufferByte) img.getRaster().getDataBuffer();
			byte[] raw = buffer.getData();
			byte[] encryptedData = cipher.doFinal(raw);

			buffer = new DataBufferByte(encryptedData, encryptedData.length);

			Raster raster = Raster.createRaster(img.getSampleModel(), buffer, new Point());
			encrypted = new BufferedImage(img.getWidth(), img.getHeight(), img.getType());
			encrypted.setData(raster);

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return encrypted;
	}

	public static BufferedImage encrypt(BufferedImage img, byte[] key, byte[] iv) {
		BufferedImage encrypted = null;

		try {
			SecretKey keySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParam = new IvParameterSpec(iv);

			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParam);

			DataBufferByte buffer = (DataBufferByte) img.getRaster().getDataBuffer();
			byte[] raw = buffer.getData();
			byte[] encryptedData = cipher.doFinal(raw);

			buffer = new DataBufferByte(encryptedData, encryptedData.length);

			Raster raster = Raster.createRaster(img.getSampleModel(), buffer, new Point());
			encrypted = new BufferedImage(img.getWidth(), img.getHeight(), img.getType());
			encrypted.setData(raster);

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}

		return encrypted;
	}

	public static BufferedImage diff(BufferedImage lhs, BufferedImage rhs) {
		byte[] data1 = ((DataBufferByte) lhs.getRaster().getDataBuffer()).getData();
		byte[] data2 = ((DataBufferByte) rhs.getRaster().getDataBuffer()).getData();

		byte[] data = new byte[data1.length];
		for (int i = 0; i < data.length; ++i) {
			data[i] = (byte) (data1[i] ^ data2[i]);
		}

		Raster raster = Raster.createRaster(lhs.getSampleModel(), new DataBufferByte(data, data.length), new Point());
		BufferedImage diff = new BufferedImage(lhs.getWidth(), lhs.getHeight(), lhs.getType());
		diff.setData(raster);

		return diff;
	}
}
