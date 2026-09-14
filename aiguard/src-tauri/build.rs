// 注意：替换 icons/*.ico 后 cargo 不会自动重链（icon 不在 rerun-if-changed 列表），
// 需改动本文件内容（哪怕只是注释）强制重编构建脚本，新图标才会嵌入 exe。
// v5：补齐 DPI 中间尺寸帧（20/40/96）+ 小尺寸 alpha 边缘硬化，解决任务栏图标发糊。
fn main() {
    tauri_build::build();
}
