.PHONY: all
all: github_banner_dark.png

github_banner_dark.png.tmp: dark_left.png.tmp dark_right.png.tmp
	gm convert -extent 1536x1000 -draw "image Over 700,-48,836,1024 dark_right.png.tmp" -shave 0x256 -resize 890x dark_left.png.tmp $@

dark_left.png.tmp: dark.png
	gm convert $< -crop 700x1024+0+0 $@

dark_right.png.tmp: dark.png
	gm convert $< -crop 836x1024+700+0 $@

%.png: %.png.tmp
	oxipng -omax -a -Z -s --out $@ $<

.PHONY: clean
clean:
	rm -f github_banner* *.tmp
