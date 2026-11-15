import { useSyncExternalStore } from 'react';

/**
 * Minimal history-API router.
 *
 * The console previously kept its location in component state, which meant the
 * browser back button and deep links did not work. This is deliberately tiny (no
 * dependency): match a path, render a page, keep history honest.
 */

export const ROUTES = [
  'overview',
  'assets',
  'scans',
  'findings',
  'reports',
  'schedules',
  'coverage',
  'integrations',
  'settings',
  'administration',
] as const;

export type RouteName = (typeof ROUTES)[number];

/** Routes that only make sense for some roles; the layout also gates them. */
export const ROUTE_META: Record<RouteName, { title: string; description: string; adminOnly?: boolean; requiresWrite?: boolean }> = {
  overview: { title: 'Overview', description: 'Posture, priorities and what is running right now' },
  assets: { title: 'Assets', description: 'What is in scope and when each asset was last assessed' },
  scans: { title: 'Scans', description: 'Start an assessment and follow it to completion' },
  findings: { title: 'Findings', description: 'Investigate and track vulnerabilities across the estate' },
  reports: { title: 'Reports', description: 'Export findings and assessment results' },
  schedules: { title: 'Schedules', description: 'Recurring assessments and their last run' },
  coverage: { title: 'Rule coverage', description: 'Services seen in scans that no detection rule covers' },
  integrations: { title: 'Integrations', description: 'Connected systems and their delivery status' },
  settings: { title: 'Settings', description: 'Account, password and console preferences' },
  administration: { title: 'Administration', description: 'Users, roles and the audit trail', adminOnly: true },
};

const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((fn) => fn());
}

if (typeof window !== 'undefined') {
  window.addEventListener('popstate', emit);
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function snapshot(): string {
  if (typeof window === 'undefined') return '/overview';
  return window.location.pathname || '/overview';
}

/** Current pathname, kept in sync with browser navigation. */
export function usePathname(): string {
  const path = useSyncExternalStore(subscribe, snapshot, () => '/overview');
  return path.split('?')[0];
}

/** Current query string (without the leading `?`). */
export function useSearch(): string {
  const path = useSyncExternalStore(subscribe, () => (typeof window === 'undefined' ? '' : window.location.search), () => '');
  return path;
}

export function navigate(to: string, options: { replace?: boolean; keepScroll?: boolean } = {}) {
  if (typeof window === 'undefined') return;
  const target = to.startsWith('/') ? to : `/${to}`;
  if (target === window.location.pathname + window.location.search) return;
  if (options.replace) window.history.replaceState({}, '', target);
  else window.history.pushState({}, '', target);
  emit();
  if (!options.keepScroll) window.scrollTo({ top: 0 });
}

/** Route name for a pathname, falling back to overview. */
export function routeOf(pathname: string): RouteName {
  const first = pathname.split('/').filter(Boolean)[0];
  return (ROUTES as readonly string[]).includes(first) ? (first as RouteName) : 'overview';
}

/** True when the current location belongs to this route (supports trailing ids). */
export function isActive(route: RouteName, pathname: string): boolean {
  return routeOf(pathname) === route;
}

/** Read one query parameter without re-rendering the whole tree. */
export function useQueryParam(name: string): string | null {
  const search = useSearch();
  return new URLSearchParams(search).get(name);
}
