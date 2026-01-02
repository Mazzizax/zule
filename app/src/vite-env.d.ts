/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GATEKEEPER_URL: string;
  readonly VITE_GATEKEEPER_ANON_KEY: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
