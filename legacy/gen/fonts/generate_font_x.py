#!/usr/bin/env python3
from PIL import Image


class Img(object):
    def __init__(self, fn):
        im = Image.open(fn)
        self.w, self.h = im.size
        self.data = list(im.getdata())

    def pixel(self, r, c):
        p = self.data[r + c * self.w]
        if p == (255, 255, 255):
            return "0"
        if p == (0, 0, 0):
            return "1"
        if p == (255, 0, 255):
            return None
        raise Exception("Unknown color", p)


# def convert(imgfile, outfile):
#     s='ÁÂÄÀÃÅÇÉÊËÈÍÎÏÌÑÓÔÖÒÕÚÛÜÙÝŶŸỲáâäàãåçéêëèíîïìñóôöòõúûüùýŷÿỳ¡¿“”‘’…°●○•'
#     print("FONT_X_COUNT ", len(s))
#     img = Img(imgfile)
#     cur = ""
#     i = 0
#     with open(outfile, "w") as f:
#         for c in s:
#             if c == '¡':
#                 i = 64
#             x = (i % 16) * 10
#             y = (i // 16) * 13
#             cur = ""
#             cur1 = ""
#             while img.pixel(x, y) is not None:
#                 val_tmp = "".join(img.pixel(x, y + j) for j in range(11))
#                 val = "".join(img.pixel(x, y + j) for j in range(8))
#                 val1 = "".join(img.pixel(x, y + j + 8) for j in range(3))
#                 x += 1
#                 cur += "\\x%02x" % int(val, 2)
#                 cur1 += "\\x%02x" % (int(val1, 2)<<5)
#             cur = "\\x%02x" % (len(cur) // 4) + cur + cur1
#             i += 1
#             f.write('\t/* 0x%02x %c */ (uint8_t *)"%s",\n' % (ord(c), c, cur))


def convert(imgfile, outfile):
    s = "ÁÂÄÀÃÅÇÉÊËÈÍÎÏÌÑÓÔÖÒÕÚÛÜÙÝŶŸỲáâäàãåçéêëèíîïìñóôöòõúûüùýŷÿỳ¡¿“”‘’…°●○•"
    print("FONT_X_COUNT ", len(s))
    img = Img(imgfile)
    cur = ""
    i = 0
    with open(outfile, "w") as f:
        for c in s:
            if c == "¡":
                i = 64
            x = (i % 16) * 10
            y = (i // 16) * 13
            cur = ""
            cur1 = ""
            while img.pixel(x, y) is not None:
                # val_tmp = "".join(img.pixel(x, y + j) for j in range(11))
                val = "".join(img.pixel(x, y + j) for j in range(8))
                val1 = "".join(img.pixel(x, y + j + 8) for j in range(3))
                x += 1
                cur += "\\x%02x" % int(val, 2)
                cur1 += "\\x%02x" % (int(val1, 2) << 5)
            cur = "\\x%02x" % (len(cur) // 4) + cur + cur1
            i += 1
            f.write(
                '    case 0x%02x: /* %c */\n      return (uint8_t *)"%s";\n'
                % (ord(c), c, cur)
            )


convert("fonts/font_x.png", "font_x.inc")
