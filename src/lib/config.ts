import { ApiError } from './types.ts';
export interface PassportConfig {
  publicUrl: string;
  storageKey: string;
  databaseUrl: string;
  frameAncestors: readonly string[];
  signInUrl: string;
}
export interface PassportConfigInput {
  publicUrl?: string;
  storageKey?: string;
  databaseUrl?: string;
  allowedEmbedOrigins?: string[];
  signInUrl?: string;
}
let active: Readonly<PassportConfig> | undefined;
function origin(value: string, field: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new ApiError(500, 'configuration_error', `${field} must be a trusted HTTPS origin.`); }
  if (url.protocol !== 'https:' || /[*\s]/.test(url.hostname) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new ApiError(500, 'configuration_error', `${field} must be a trusted HTTPS origin without credentials, path or query.`);
  return url.origin;
}
export function resolveConfig(input: PassportConfigInput = {}): PassportConfig {
  const publicUrl = origin(input.publicUrl ?? process.env.MULTIPASS_PUBLIC_URL ?? '', 'MULTIPASS_PUBLIC_URL');
  const storageKey = input.storageKey ?? process.env.MULTIPASS_STORAGE_KEY ?? '';
  if (storageKey.length < 32) throw new ApiError(500, 'configuration_error', 'MULTIPASS_STORAGE_KEY must contain at least 32 characters from a high-entropy host-side secret.');
  const databaseUrl = input.databaseUrl ?? process.env.MULTIPASS_DATABASE_URL ?? '';
  let database: URL;
  try { database = new URL(databaseUrl); } catch { throw new ApiError(500, 'configuration_error', 'MULTIPASS_DATABASE_URL must identify your PostgreSQL database.'); }
  if (!['postgres:', 'postgresql:'].includes(database.protocol)) throw new ApiError(500, 'configuration_error', 'MULTIPASS_DATABASE_URL must identify your PostgreSQL database.');
  const embedded = input.allowedEmbedOrigins ?? (process.env.MULTIPASS_EMBED_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean);
  const signIn = input.signInUrl ?? process.env.MULTIPASS_SIGN_IN_URL ?? '/login';
  const signInUrl = new URL(signIn, publicUrl);
  if (signInUrl.protocol !== 'https:' || signInUrl.username || signInUrl.password) throw new ApiError(500, 'configuration_error', 'Host sign-in URL must use HTTPS without URL credentials.');
  return { publicUrl, storageKey, databaseUrl, frameAncestors: Object.freeze(["'self'", ...embedded.map(value => origin(value, 'Embedding origin'))]), signInUrl: signInUrl.href };
}
/** One installation/database per process. Use separate processes for tenants. */
export function configurePassport(input: PassportConfigInput = {}): Readonly<PassportConfig> {
  const next = resolveConfig(input);
  if (active && JSON.stringify(next) !== JSON.stringify(active)) throw new ApiError(500, 'configuration_error', 'This process is already configured for another Passport installation.');
  return active ??= Object.freeze(next);
}
export function getConfig(): Readonly<PassportConfig> { return active ?? configurePassport(); }
