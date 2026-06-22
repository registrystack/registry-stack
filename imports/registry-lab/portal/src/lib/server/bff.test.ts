import { describe, it, expect } from 'vitest';
import { heartbeatFrame } from './bff';

describe('SSE heartbeat framing', () => {
  it('is a real named event, not an SSE comment (EventSource swallows comments)', () => {
    // Regression guard: the heartbeat used to be a `: comment`, which EventSource
    // silently drops. That meant the client watchdog never saw it and tripped the
    // reconnect pill ~15s after the last trace. A named `event: heartbeat` frame is
    // delivered to the client's addEventListener('heartbeat', ...) handler.
    const frame = heartbeatFrame();
    expect(frame.startsWith(':')).toBe(false);
    expect(frame).toMatch(/^event: heartbeat\n/);
    expect(frame).toMatch(/\ndata: /);
    expect(frame.endsWith('\n\n')).toBe(true);
  });
});
