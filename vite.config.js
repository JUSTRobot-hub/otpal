import { defineConfig } from 'vite';
import { resolve } from 'node:path';

export default defineConfig({
  // Relative asset URLs: the phone page is served from /s/<token>/.
  base: './',
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  envPrefix: ['VITE_', 'TAURI_ENV_*'],
  build: {
    target: 'es2022',
    outDir: 'dist',
    rollupOptions: { input: { main: resolve('index.html'), phone: resolve('phone.html') } },
  },
});
