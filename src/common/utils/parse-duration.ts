export function parseDuration(value: string | number | undefined): number {
  if (typeof value === 'number') return value;
  if (!value) return 0;
  const s = String(value);
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  const m = s.match(/^(\d+)([smhd])$/);
  if (!m) return 0;
  const num = parseInt(m[1], 10);
  const unit = m[2];
  const map: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return num * map[unit];
}
