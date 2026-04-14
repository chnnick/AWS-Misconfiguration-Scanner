import path from 'path';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const frontendDir = __dirname;
  const repoRoot = path.resolve(frontendDir, '..');
  const env = {
    ...loadEnv(mode, repoRoot, ''),
    ...loadEnv(mode, frontendDir, ''),
  };
  const apiBaseUrl = env.API_BASE_URL ?? env.VITE_API_BASE_URL ?? '';

  return {
    define: {
      'process.env.API_BASE_URL': JSON.stringify(apiBaseUrl),
    },
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(frontendDir, './src'),
      },
    },
    optimizeDeps: {
      exclude: ['lucide-react'],
    },
  };
});
