import { Transport, type ClientOptions } from '../core.ts'

/** Builds a generated product client over its own transport, as the per-service file does. */
export function make<C>(Client: new (transport: Transport) => C, options: ClientOptions): C {
  return new Client(new Transport(options))
}
