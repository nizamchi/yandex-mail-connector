// Thin local shim for node-notifier (optional dynamic import; externalized in
// the esbuild bundle, may be absent at runtime). tools.ts casts the import
// result to its own shape, so a bare ambient declaration is enough to resolve
// the module for tsc. v2.6.0 P-2 typecheck layer.
declare module 'node-notifier';
