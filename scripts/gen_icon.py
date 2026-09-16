# -*- coding: utf-8 -*-
"""
AI 安全卫士 · 任务栏图标生成器
设计对齐应用内图标（rail-logo 容器 + hero 盾牌）：
  深墨绿圆角方块底 + 守护绿渐变实底盾牌 + 白色圆头对勾 + 盾内白 alpha 描边
输出：src-tauri/icons/icon.ico（16/24/32/48/64/128/256 全尺寸独立渲染）
"""
from PIL import Image, ImageDraw
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "src-tauri", "icons"))
SS = 4  # 超采样倍数

# ── 色板（与 src/ui.css 同源）──
BG_TOP = (22, 36, 29)      # 深墨绿亮端 #16241d
BG_BOT = (9, 15, 12)       # 深墨绿暗端 #090f0c
SHIELD_TOP = (28, 178, 119)  # 守护绿亮端 #1cb277
SHIELD_BOT = (11, 115, 80)   # 守护绿暗端 #0b7350
CHECK = (255, 255, 255, 255)
INNER_RING = (255, 255, 255, 88)  # 盾内白描边 ~35%


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def vgrad(size, c1, c2, horizontal=False):
    """对角/垂直渐变小图放大（快且平滑）"""
    g = Image.new("RGB", (64, 64))
    px = g.load()
    for y in range(64):
        for x in range(64):
            t = ((x + y) / 126.0) if horizontal else (y / 63.0)
            px[x, y] = lerp(c1, c2, t)
    return g.resize(size, Image.BILINEAR)


def bez(p0, p1, p2, p3, n=28):
    pts = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        pts.append((
            u ** 3 * p0[0] + 3 * u ** 2 * t * p1[0] + 3 * u * t ** 2 * p2[0] + t ** 3 * p3[0],
            u ** 3 * p0[1] + 3 * u ** 2 * t * p1[1] + 3 * u * t ** 2 * p2[1] + t ** 3 * p3[1],
        ))
    return pts


def shield_pts(scale=1.0):
    """viewBox=24 的盾牌轮廓（与 App.tsx HeroShieldArt 同一路径），可整体缩放"""
    cx, cy = 12.0, 11.75
    raw = [(12, 3), (19, 6), (19, 11)]
    raw += bez((19, 11), (19, 15.4), (16.1, 19.3), (12, 20.5))
    raw += bez((12, 20.5), (7.9, 19.3), (5, 15.4), (5, 11))
    raw += [(5, 6)]
    return [((cx + (x - cx) * scale), (cy + (y - cy) * scale)) for x, y in raw]


def to_canvas(pts, S, m, k):
    """VB 坐标 → 画布：盾水平中心（VB x=12）对齐画布中心，盾顶（VB y=3）落在上边距 m 处"""
    return [(S / 2 + (x - 12.0) * k, m + (y - 3.0) * k) for x, y in pts]


def render(size):
    S = size * SS
    small = size <= 48
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 盾牌几何：按高度撑满画布（上下各留 2% 安全边距），水平居中。
    # 盾 VB 边界：x 5..19（宽 14），y 3..20.5（高 17.5）——宽高比 0.8:1 决定宽度约占格子 77%。
    m = S * 0.02
    k = (S - 2 * m) / 17.5

    # 2) 守护绿渐变实底盾牌（纯净无描边圈）
    sh_pts = to_canvas(shield_pts(), S, m, k)
    sx0 = min(p[0] for p in sh_pts)
    sx1 = max(p[0] for p in sh_pts)
    sy0 = min(p[1] for p in sh_pts)
    sy1 = max(p[1] for p in sh_pts)
    sh_grad = vgrad((S, S), SHIELD_TOP, SHIELD_BOT).convert("RGBA")
    sh_mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(sh_mask).polygon(sh_pts, fill=255)
    img.paste(sh_grad, (0, 0), sh_mask)

    # 4) 白色圆头对勾（与 hero 插画同形态：M9 11.5 L11.2 13.7 L15.5 9.5）
    check = [(9, 11.5), (11.2, 13.7), (15.5, 9.5)]
    cw = k * (5.0 if small else 3.8)  # 勾线宽（VB 单位换算）
    cps = to_canvas(check, S, m, k)
    d.line(cps, fill=CHECK, width=int(cw), joint="curve")
    r = cw / 2
    for p in (cps[0], cps[-1]):
        d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=CHECK)

    out = img.resize((size, size), Image.LANCZOS)

    # 小/中尺寸帧：alpha 边缘硬化，抵消任务栏 DPI 拉伸的发虚感
    if size <= 48:
        lut = []
        for v in range(256):
            if v < 48:
                t = 0
            elif v > 208:
                t = 255
            else:
                t = int((v - 48) / 160 * 255)
            lut.append(t)
        out.putalpha(out.getchannel("A").point(lut))

    return out


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    # 覆盖 Windows 全 DPI 任务栏需求（16/20/24/32/40/48…），避免系统拿近邻帧拉伸发糊
    sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
    imgs = {s: render(s) for s in sizes}
    ico_path = os.path.join(OUT_DIR, "icon.ico")
    imgs[256].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=[imgs[s] for s in sizes if s != 256],
    )
    print("ICO written:", ico_path)

    # 预览拼图：浅色 / 深色两行
    pad = 12
    row = [256, 128, 96, 64, 48, 40, 32, 24, 20, 16]
    cell_h = 256 + pad * 2
    w = sum(row) + pad * (len(row) + 1)
    h = cell_h * 2 + 60
    canvas = Image.new("RGB", (w, h), (246, 247, 248))
    dd = ImageDraw.Draw(canvas)
    dd.rectangle([0, h // 2, w, h], fill=(15, 23, 20))
    x = pad
    for s in row:
        im = imgs[s]
        y = (cell_h - s) // 2
        canvas.paste(im, (x, y), im)
        y2 = cell_h + (cell_h - s) // 2
        canvas.paste(im, (x, y2), im)
        x += s + pad
    preview = os.path.join(HERE, "icon_preview.png")
    canvas.save(preview)
    print("Preview:", preview)


if __name__ == "__main__":
    main()
