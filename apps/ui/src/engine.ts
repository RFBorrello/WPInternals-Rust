import init, * as wasm from '../../../crates/wpi-wasm/pkg/wpi_wasm';
let ready: Promise<void> | undefined;
export function initialize(): Promise<void> { return ready ??= init().then(() => undefined); }
export { wasm };
