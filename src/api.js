// The desktop app's Rust side owns the unlocked vault. Nothing here returns a secret key or an
// encryption key; the most that comes back is one six-digit code on request.
export const inTauri = () => '__TAURI_INTERNALS__' in window;

// Tauri rejects with plain strings; callers expect Error objects with a message.
const call = async (command, args) => {
  try {
    return await (await import('@tauri-apps/api/core')).invoke(command, args);
  } catch (e) {
    throw e instanceof Error ? e : new Error(String(e));
  }
};

export const bindingAvailable = async () => inTauri() && call('dpapi_available');

export const api = {
  exists: () => call('vault_exists'),
  openAuthorPage: () => call('open_author_page'),
  create: (password, bind) => call('create_vault', { password, bind }),
  unlock: (password) => call('unlock', { password }),
  info: () => call('session_info'),
  lock: () => call('lock_vault'),
  list: () => call('list_accounts'),
  code: async (id) => (await call('get_code', { id })).code,
  add: (accounts) => call('add_accounts', { accounts }),
  remove: (id) => call('remove_account', { id }),
  verify: (password) => call('verify_password', { password }),
  upgrade: (password, wantBind) => call('upgrade_vault', { password, wantBind }),
  touch: () => call('touch'),
  setIdle: (minutes) => call('set_idle_minutes', { minutes }),
  onLocked: async (fn) => (await import('@tauri-apps/api/event')).listen('vault-locked', fn),
};
