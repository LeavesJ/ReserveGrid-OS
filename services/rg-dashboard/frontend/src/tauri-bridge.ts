/**
 * Tauri IPC bridge for rg-desktop.
 *
 * Detects whether the frontend is running inside a Tauri webview or a
 * regular browser. When inside Tauri, API calls route through IPC commands
 * instead of HTTP fetch. When in a browser, falls through to standard fetch
 * so the existing rg-dashboard proxy path works unchanged.
 *
 * This module is the ONLY place that imports `@tauri-apps/api`.
 * All other code continues to use the same hook interface.
 */

/* ── Tauri detection ── */

/**
 * Returns true if the frontend is running inside a Tauri webview.
 * Tauri injects `window.__TAURI_INTERNALS__` into the webview context.
 */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/* ── IPC invoke wrapper ── */

/**
 * Dynamically import and call Tauri's invoke function.
 * This avoids a hard dependency on @tauri-apps/api at build time,
 * allowing the same frontend bundle to work in both Tauri and browser contexts.
 */
async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // @ts-expect-error — Tauri injects this globally in the webview
  const { invoke } = window.__TAURI_INTERNALS__;
  return invoke(cmd, args) as Promise<T>;
}

/* ── Route mapping ── */

interface ParsedRoute {
  service: string;
  path: string;
}

/**
 * Parse a fetch URL like "/api/verifier/stats" into service + path.
 * Returns null for URLs that do not match the /api/{service}/{path} pattern.
 */
function parseApiRoute(url: string): ParsedRoute | null {
  const match = url.match(/^\/api\/(verifier|templates|gateway|health|dashboard)(?:\/(.*))?$/);
  if (!match) return null;

  const service = match[1];
  const path = match[2] ?? "";

  return { service, path };
}

/* ── Tauri-aware fetch replacement ── */

/**
 * Drop-in replacement for fetch() that routes through Tauri IPC when
 * running inside the desktop app.
 *
 * For non-API URLs or when not in Tauri, delegates to standard fetch.
 */
export async function tauriFetch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  if (!isTauri()) {
    return fetch(url, init);
  }

  const route = parseApiRoute(url);
  if (!route) {
    // Not an API route; fall through to regular fetch (e.g., static assets).
    return fetch(url, init);
  }

  const method = init?.method?.toUpperCase() ?? "GET";

  try {
    let result: unknown;

    if (route.service === "health") {
      // /api/health → health_check command
      result = await tauriInvoke("health_check");
    } else if (route.service === "dashboard") {
      // /api/dashboard/settings → get_dashboard_settings command
      result = await tauriInvoke("get_dashboard_settings");
    } else {
      // /api/{service}/{path} → proxy_request command
      let body: unknown = undefined;
      if (init?.body) {
        body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
      }

      result = await tauriInvoke("proxy_request", {
        service: route.service,
        path: route.path,
        method,
        body: body ?? null,
      });
    }

    // Wrap the IPC result in a Response-like object for compatibility
    // with the existing fetchJson/postJson helpers in useApi.ts.
    const jsonStr = JSON.stringify(result);
    return new Response(jsonStr, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    // IPC errors become network-level failures.
    const message = err instanceof Error ? err.message : String(err);
    return new Response(JSON.stringify({ error: message }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }
}

/* ── License key IPC commands ── */

export interface LicenseStatus {
  has_key: boolean;
  valid: boolean;
  tier: string | null;
}

export async function getLicenseStatus(): Promise<LicenseStatus> {
  if (!isTauri()) {
    return { has_key: false, valid: false, tier: null };
  }
  return tauriInvoke<LicenseStatus>("get_license_status");
}

export async function setLicenseKey(key: string): Promise<{ ok: boolean; tier?: string }> {
  if (!isTauri()) {
    return { ok: false };
  }
  return tauriInvoke("set_license_key", { key });
}

export async function clearLicense(): Promise<void> {
  if (!isTauri()) return;
  await tauriInvoke("clear_license");
}

/* ── Update IPC commands ── */

export interface UpdateCheckResult {
  update_available: boolean;
  version: string | null;
  body: string | null;
  current_version: string;
}

export async function checkForUpdate(): Promise<UpdateCheckResult> {
  if (!isTauri()) {
    return { update_available: false, version: null, body: null, current_version: "unknown" };
  }
  return tauriInvoke<UpdateCheckResult>("check_for_update");
}

export async function installUpdate(): Promise<string> {
  if (!isTauri()) {
    return "not running in desktop app";
  }
  return tauriInvoke<string>("install_update");
}
