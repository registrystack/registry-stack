export function writeSummary(data) {
  const path = __ENV.K6_SUMMARY_PATH;
  if (!path) {
    return {};
  }
  return { [path]: `${JSON.stringify(data, null, 2)}\n` };
}
