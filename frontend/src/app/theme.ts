import { createTheme, type MantineColorsTuple } from '@mantine/core';

/**
 * Clanker Guard design tokens.
 *
 * One source of truth for colour, spacing, typography and radii. The interface is
 * built from flat, bordered surfaces: no gradients, no glow, no glassmorphism.
 * Colour carries meaning (severity, status) and is always paired with a label or
 * icon so it is not the only signal.
 */

/** Semantic colours, identical in both themes so status means the same thing. */
export const semantic = {
  primary: '#2563EB',
  critical: '#DC4E5A',
  high: '#E18A43',
  medium: '#D6A13B',
  low: '#2B9B7C',
  success: '#2B9B7C',
  info: '#3B6FD4',
  neutral: '#64748B',
} as const;

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

/** Severity → colour, label and short description. Never colour alone. */
export const severityMeta: Record<Severity, { color: string; label: string; hint: string }> = {
  critical: { color: semantic.critical, label: 'Critical', hint: 'Exploitable now or actively exploited' },
  high: { color: semantic.high, label: 'High', hint: 'Serious exposure, prioritise this cycle' },
  medium: { color: semantic.medium, label: 'Medium', hint: 'Requires a planned fix' },
  low: { color: semantic.low, label: 'Low', hint: 'Hardening / defence in depth' },
  informational: { color: semantic.neutral, label: 'Info', hint: 'Context only, not a vulnerability' },
};

export function severityOf(value: string | null | undefined): Severity {
  const key = (value ?? '').toLowerCase();
  if (key === 'critical' || key === 'high' || key === 'medium' || key === 'low') return key;
  return 'informational';
}

/** Scan/asset lifecycle colours. */
export const statusMeta: Record<string, { color: string; label: string }> = {
  queued: { color: semantic.info, label: 'Queued' },
  pending: { color: semantic.info, label: 'Pending' },
  running: { color: semantic.primary, label: 'Running' },
  completed: { color: semantic.success, label: 'Completed' },
  completed_with_errors: { color: semantic.high, label: 'Completed with errors' },
  failed: { color: semantic.critical, label: 'Failed' },
  cancelled: { color: semantic.neutral, label: 'Cancelled' },
  skipped: { color: semantic.neutral, label: 'Skipped' },
  open: { color: semantic.critical, label: 'Open' },
  resolved: { color: semantic.success, label: 'Resolved' },
  accepted_risk: { color: semantic.medium, label: 'Accepted risk' },
  false_positive: { color: semantic.neutral, label: 'False positive' },
  connected: { color: semantic.success, label: 'Connected' },
  disconnected: { color: semantic.neutral, label: 'Not connected' },
};

export function statusOf(value: string | null | undefined): { color: string; label: string } {
  const key = (value ?? '').toLowerCase();
  if (statusMeta[key]) return statusMeta[key];
  return { color: semantic.neutral, label: value ? value.replace(/_/g, ' ') : 'Unknown' };
}

/* Mantine expects 10 shades per colour family. Index 6 is the semantic colour
 * itself, so `color="brand"` reads as the documented blue rather than a tint. */
const mix = (value: number, target: number, pct: number) => Math.round(value + (target - value) * (pct / 100));

const scale = (hex: string): MantineColorsTuple => {
  const base = hex.replace('#', '');
  const rgb = [0, 2, 4].map((i) => parseInt(base.slice(i, i + 2), 16));
  const hexOf = (values: number[]) => `#${values.map((n) => Math.min(255, Math.max(0, n)).toString(16).padStart(2, '0')).join('')}`;
  const towardWhite = [94, 85, 74, 62, 44, 22];
  const towardBlack = [0, 12, 26, 40];
  return [
    ...towardWhite.map((pct) => hexOf(rgb.map((v) => mix(v, 255, pct)))),
    ...towardBlack.map((pct) => hexOf(rgb.map((v) => mix(v, 0, pct)))),
  ] as unknown as MantineColorsTuple;
};

export const brand: MantineColorsTuple = scale(semantic.primary);
export const danger: MantineColorsTuple = scale(semantic.critical);
export const success: MantineColorsTuple = scale(semantic.success);
export const warn: MantineColorsTuple = scale(semantic.medium);
export const highOrange: MantineColorsTuple = scale(semantic.high);

/** Surface tokens per theme. Components read these instead of hardcoded hex. */
export const surfaces = {
  dark: {
    background: '#0B1220',
    // level 1: content panels
    surface: '#172235',
    // level 2: nested panels, table bodies, inner cards
    surfaceElevated: '#233247',
    // level 0.5: section headers inside a panel
    sectionHeader: '#1D2C40',
    border: '#34445B',
    borderStrong: '#465364',
    text: '#E8EEF7',
    textMuted: '#A5B4C7',
    tableHeader: '#1D2C40',
    tableRowHover: '#243349',
    codeBg: '#293241',
    codeBorder: '#465364',
    codeText: '#F1F5F9',
    codeMuted: '#AEBBCC',
  },
  light: {
    background: '#F5F7FB',
    surface: '#FFFFFF',
    surfaceElevated: '#EFF3F8',
    sectionHeader: '#F1F5F9',
    border: '#D8E0EA',
    borderStrong: '#CDD5DF',
    text: '#172235',
    textMuted: '#64748B',
    tableHeader: '#F1F5F9',
    tableRowHover: '#F8FAFC',
    codeBg: '#E9EDF2',
    codeBorder: '#CDD5DF',
    codeText: '#263445',
    codeMuted: '#64748B',
  },
} as const;

export type Scheme = keyof typeof surfaces;

/** Flat panel style for a given nesting level: 1 = content, 2 = nested. */
export function panelStyle(scheme: Scheme, level: 1 | 2 = 1): React.CSSProperties {
  const t = surfaceTokens(scheme);
  return {
    background: level === 1 ? t.surface : t.surfaceElevated,
    border: `1px solid ${t.border}`,
    boxShadow: 'none',
  };
}

export function surfaceTokens(scheme: Scheme) {
  return surfaces[scheme === 'light' ? 'light' : 'dark'];
}

/** Spacing / radius / type scale used across the app. */
export const tokens = {
  radius: { sm: 6, md: 8, lg: 12 },
  space: { xs: 6, sm: 10, md: 16, lg: 24, xl: 32 },
  font: {
    body: 14,
    bodyLarge: 15,
    small: 12,
    tiny: 11,
    mono: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
  },
  headerHeight: 56,
  sidebarWidth: 248,
  sidebarCollapsedWidth: 68,
} as const;

export const theme = createTheme({
  primaryColor: 'brand',
  primaryShade: { light: 6, dark: 5 },
  colors: { brand, danger, success, warn, highOrange },
  fontFamily: 'Inter, system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
  fontFamilyMonospace: tokens.font.mono,
  // Headings share the body family: the hierarchy comes from weight and size, not
  // a second typeface fighting for attention.
  headings: { fontFamily: 'Inter, system-ui, sans-serif', fontWeight: '600', sizes: {
    h1: { fontSize: '22px', lineHeight: '1.25' },
    h2: { fontSize: '17px', lineHeight: '1.3' },
    h3: { fontSize: '15px', lineHeight: '1.35' },
    h4: { fontSize: '14px', lineHeight: '1.4' },
  } },
  fontSizes: { xs: '11px', sm: '12px', md: '13.5px', lg: '15px', xl: '17px' },
  radius: { xs: '6px', sm: '8px', md: '8px', lg: '12px', xl: '16px' },
  spacing: { xs: '6px', sm: '10px', md: '16px', lg: '24px', xl: '32px' },
  defaultRadius: 'md',
  components: {
    Button: { defaultProps: { radius: 'md' } },
    Card: { defaultProps: { radius: 'lg', withBorder: true } },
    Paper: { defaultProps: { radius: 'lg', withBorder: true } },
    Table: { defaultProps: { highlightOnHover: true, verticalSpacing: 'xs', horizontalSpacing: 'sm' } },
    Modal: { defaultProps: { radius: 'lg', centered: true } },
    Drawer: { defaultProps: { radius: 'lg' } },
    Tooltip: { defaultProps: { withArrow: true, openDelay: 250 } },
    TextInput: { defaultProps: { radius: 'md' } },
    Select: { defaultProps: { radius: 'md' } },
    Badge: { defaultProps: { radius: 'sm' } },
  },
});
