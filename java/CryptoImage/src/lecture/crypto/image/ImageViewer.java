package lecture.crypto.image;

import java.awt.Graphics;
import java.awt.image.BufferedImage;

import javax.swing.JFrame;

public class ImageViewer extends JFrame {

	private int _titlebarHeight;
	private BufferedImage _img = null;

	public ImageViewer(String title, BufferedImage img) {
		this._img = img;
		this.setDefaultCloseOperation(EXIT_ON_CLOSE);
		this.setTitle(title);
		this.setVisible(true);

		_titlebarHeight = getInsets().top;
		this.setSize(img.getWidth(), img.getHeight() + _titlebarHeight);
	}

	@Override
	public void paint(Graphics g) {
		if (_img != null) {
			g.drawImage(_img, 0, _titlebarHeight, null);
		}
	}
}
