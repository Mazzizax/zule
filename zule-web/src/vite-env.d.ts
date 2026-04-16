/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly ZULE_URL: string;
  readonly ZULE_PUBLISHABLE_KEY: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
