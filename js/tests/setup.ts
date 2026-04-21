import 'fake-indexeddb/auto';
import { beforeEach } from 'vitest';

const fallbackLocalStorage = (() => {
  const storage = new Map<string, string>();
  return {
    getItem(key: string): string | null {
      return storage.has(key) ? storage.get(key)! : null;
    },
    setItem(key: string, value: string): void {
      storage.set(String(key), String(value));
    },
    removeItem(key: string): void {
      storage.delete(String(key));
    },
    clear(): void {
      storage.clear();
    },
    key(index: number): string | null {
      return [...storage.keys()][index] ?? null;
    },
    get length(): number {
      return storage.size;
    },
  };
})();

if (
  typeof globalThis.localStorage === 'undefined'
  || typeof globalThis.localStorage?.getItem !== 'function'
  || typeof globalThis.localStorage?.setItem !== 'function'
  || typeof globalThis.localStorage?.removeItem !== 'function'
) {
  Object.defineProperty(globalThis, 'localStorage', {
    value: fallbackLocalStorage,
    configurable: true,
    writable: true,
  });
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
}

beforeEach(async () => {
  globalThis.localStorage.clear();
  await deleteDatabase('aun-keystore');
  await deleteDatabase('aun-secret-store');
});
