# -*- coding: utf-8 -*-
"""裁掉截图顶部的预览标题条（2x DPI 下 56px），更像真实应用截图。"""
import os
from PIL import Image

D = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "screenshots"))
for f in sorted(os.listdir(D)):
    if not f.endswith(".png"):
        continue
    p = os.path.join(D, f)
    im = Image.open(p)
    w, h = im.size
    im.crop((0, 56, w, h)).save(p)
    print("cropped:", f, w, h, "->", h - 56)
