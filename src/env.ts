export type RuntimeEnv = Env & {
  VAULTS: DurableObjectNamespace;
  SETUP_TOKEN?: string;
};
