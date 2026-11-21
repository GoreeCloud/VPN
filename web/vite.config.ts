import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, emptyOutDir: true },
  server: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: { "/v1": { target: "http://127.0.0.1:8788", changeOrigin: false } }
  }
});
