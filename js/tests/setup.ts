import 'fake-indexeddb/auto';
import { createRequire } from 'node:module';
import { beforeEach } from 'vitest';
import { collectLocalDockerIssuers, isLocalDockerHost } from './local-docker.js';

const require = createRequire(import.meta.url);

const shouldPinLocalDocker = () => process.env.AUN_TEST_DISABLE_LOCAL_DOCKER_PIN !== '1';

function installLocalDockerDnsPinning(): void {
  const pinnedIssuers = collectLocalDockerIssuers();
  const dns: any = require('node:dns');
  const dnsPromises: any = require('node:dns/promises');
  const originalLookup = dns.lookup.bind(dns);
  const originalPromiseLookup = dnsPromises.lookup.bind(dnsPromises);

  const pinnedLookup = (
    hostname: string,
    options?: any,
    callback?: ((err: NodeJS.ErrnoException | null, address: any, family?: number) => void) | null,
  ): void => {
    let lookupOptions = options;
    let lookupCallback = callback;
    if (typeof lookupOptions === 'function' && lookupCallback === undefined) {
      lookupCallback = lookupOptions;
      lookupOptions = undefined;
    }
    if (!isLocalDockerHost(hostname, pinnedIssuers)) {
      originalLookup(hostname, lookupOptions, lookupCallback);
      return;
    }
    const result = (lookupOptions && typeof lookupOptions === 'object' && !Array.isArray(lookupOptions) && (lookupOptions as { all?: unknown }).all)
      ? [{ address: '127.0.0.1', family: 4 }]
      : '127.0.0.1';
    if (typeof lookupCallback === 'function') {
      if (Array.isArray(result)) {
        lookupCallback(null, result);
      } else {
        lookupCallback(null, result, 4);
      }
      return;
    }
  };

  const pinnedPromiseLookup = async (
    hostname: string,
    options?: any,
  ): Promise<any> => {
    if (!isLocalDockerHost(hostname, pinnedIssuers)) {
      return originalPromiseLookup(hostname, options);
    }
    if (options && typeof options === 'object' && !Array.isArray(options) && (options as { all?: unknown }).all) {
      return [{ address: '127.0.0.1', family: 4 }];
    }
    return { address: '127.0.0.1', family: 4 };
  };

  Object.defineProperty(dns, 'lookup', {
    value: pinnedLookup,
    writable: true,
    configurable: true,
  });
  Object.defineProperty(dnsPromises, 'lookup', {
    value: pinnedPromiseLookup,
    writable: true,
    configurable: true,
  });
  process.env.HTTP_PROXY = '';
  process.env.HTTPS_PROXY = '';
  process.env.ALL_PROXY = '';
  process.env.http_proxy = '';
  process.env.https_proxy = '';
  process.env.all_proxy = '';
  process.env.NO_PROXY = '*';
  process.env.no_proxy = '*';
  console.log(`AUN_TEST: local docker DNS pinning enabled for ${pinnedIssuers.join(', ')}`);
}

if (shouldPinLocalDocker()) {
  installLocalDockerDnsPinning();
}

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
