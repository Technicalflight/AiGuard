# -*- coding: utf-8 -*-
"""从图标渲染函数导出 README / 社交卡用的 PNG（256px）。"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_icon

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.normpath(os.path.join(HERE, "..", "docs"))
os.makedirs(DOCS, exist_ok=True)
gen_icon.render(256).save(os.path.join(DOCS, "logo.png"))
gen_icon.render(128).save(os.path.join(DOCS, "logo-128.png"))
print("logo written:", DOCS)
