import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  envPrefix: 'GATEKEEPER_',
  server: {
    port: 3001, // Different port from main app
  },
});
