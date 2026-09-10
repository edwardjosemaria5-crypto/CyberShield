const HOST_EXPRESSION = 'import.meta.env.VITE_API_BASE_URL';
const HOST_SHIM = '(globalThis.importMetaEnv?.VITE_API_BASE_URL ?? undefined)';

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (error) {
    if (!specifier.startsWith('.') && !specifier.startsWith('file://')) {
      throw error;
    }
    const candidates = [
      `${specifier}.js`,
      `${specifier}.jsx`,
      `${specifier}/index.js`,
      `${specifier}/index.jsx`,
    ];
    for (const candidate of candidates) {
      try {
        return await nextResolve(candidate, context);
      } catch {
        // try next candidate
      }
    }
    throw error;
  }
}

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (url.endsWith('/src/services/api.js')) {
    const raw = result.source;
    const source = typeof raw === 'string' ? raw : new TextDecoder().decode(raw);
    return { ...result, source: source.split(HOST_EXPRESSION).join(HOST_SHIM), shortCircuit: true };
  }
  return result;
}