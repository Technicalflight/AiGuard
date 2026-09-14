import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Tauri expects a fixed port, fail if that port is not available
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      // Windows 关键修复：Rust 编译产物目录中的 .exe 在运行期被系统锁定（EBUSY），
      // chokidar 监听这些文件会直接抛错并终止 dev server（beforeDevCommand 失败）。
      // 同时忽略 src-tauri：Rust 代码变更由 cargo/tairi 自身负责重编译，无需前端 reload。
      ignored: ["**/target/**", "**/src-tauri/**", "**/dist/**"],
    },
  },
  // Env variables starting with TAURI_ are exposed to the frontend
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    // Tauri supports es2021
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
  },
  clearScreen: false,
});
