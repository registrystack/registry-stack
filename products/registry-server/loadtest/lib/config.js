export const SAFE_SYSTEM_TAGS = ['status', 'method', 'name', 'scenario', 'expected_response'];

export const SUMMARY_TREND_STATS = ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'];

export function positiveNumber(name, raw, fallback) {
  const value = Number(raw === undefined || raw === '' ? fallback : raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number`);
  }
  return value;
}

export function positiveInteger(name, raw, fallback) {
  const value = positiveNumber(name, raw, fallback);
  if (!Number.isInteger(value)) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

export function durationMilliseconds(name, value) {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value);
  if (!match) {
    throw new Error(`${name} must be a k6 duration using ms, s, m, or h`);
  }
  const multipliers = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
  const milliseconds = Number(match[1]) * multipliers[match[2]];
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
    throw new Error(`${name} must be a positive duration`);
  }
  return milliseconds;
}

export function startTime(...durations) {
  return `${durations.reduce((total, duration) => total + duration, 0)}ms`;
}
