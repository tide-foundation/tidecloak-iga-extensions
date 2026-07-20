import * as fs from 'fs';

/**
 * Environment resolution for the IGA E2E harness.
 *
 * Admin credentials are read from the localtest docker-compose.yml so the
 * harness needs no hard-coded secrets. They can be overridden by env vars
 * (KC_BASE_URL, KC_ADMIN_USER, KC_ADMIN_PASSWORD, KC_COMPOSE_FILE) for CI or
 * a non-default deployment.
 *
 * The password is NEVER logged by this harness.
 */

const DEFAULT_COMPOSE =
  '/home/sasha/project/tidecloak/Tidified/localtest/docker-compose.yml';

export interface KcEnv {
  baseUrl: string;
  adminUser: string;
  adminPassword: string;
}

function readComposeCreds(file: string): { user?: string; password?: string } {
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return {};
  }
  const grab = (key: string): string | undefined => {
    // Matches `KEY: value` (optionally quoted) in a docker-compose env block.
    const m = text.match(new RegExp(`${key}\\s*:\\s*["']?([^"'\\n\\r]+)["']?`));
    return m ? m[1].trim() : undefined;
  };
  return {
    user: grab('KC_BOOTSTRAP_ADMIN_USERNAME'),
    password: grab('KC_BOOTSTRAP_ADMIN_PASSWORD'),
  };
}

let cached: KcEnv | undefined;

export function kcEnv(): KcEnv {
  if (cached) return cached;
  const composeFile = process.env.KC_COMPOSE_FILE || DEFAULT_COMPOSE;
  const fromCompose = readComposeCreds(composeFile);
  const adminUser =
    process.env.KC_ADMIN_USER || fromCompose.user || 'admin';
  const adminPassword =
    process.env.KC_ADMIN_PASSWORD || fromCompose.password || '';
  if (!adminPassword) {
    throw new Error(
      `Could not resolve admin password. Set KC_ADMIN_PASSWORD or ensure ` +
        `KC_BOOTSTRAP_ADMIN_PASSWORD is present in ${composeFile}.`,
    );
  }
  cached = {
    baseUrl: process.env.KC_BASE_URL || 'http://localhost:8080',
    adminUser,
    adminPassword,
  };
  return cached;
}
