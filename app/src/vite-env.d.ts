/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly GATEKEEPER_URL: string;
  readonly GATEKEEPER_PUBLISHABLE_KEY: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
