import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AppShell,
  Badge,
  Button,
  Card,
  Grid,
  Group,
  MultiSelect,
  Switch,
  Paper,
  Progress,
  ScrollArea,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  Textarea,
  TextInput,
  ThemeIcon,
  Title,
  Tooltip,
  ActionIcon,
  useMantineColorScheme,
  Drawer,
  rem,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { Modal, PasswordInput } from '@mantine/core';
import { Burger, Divider } from '@mantine/core';
import { Loader } from '@mantine/core';
import {
  IconAlertTriangle,
  IconClockHour4,
  IconRadar2,
  IconRefresh,
  IconRobot,
  IconSend,
  IconShieldCheck,
  IconSparkles,
  IconTarget,
  IconPlugConnected,
} from '@tabler/icons-react';
import { IconLogout, IconUser } from '@tabler/icons-react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

interface Asset {
  id: number;
  name?: string | null;
  target: string;
  environment?: string | null;
  owner?: string | null;
  notes?: string | null;
  credentialed?: boolean;
  ssh_username?: string | null;
  ssh_port?: number | null;
  ssh_auth_method?: string | null;
  ssh_key_path?: string | null;
  ssh_allow_agent?: boolean;
  ssh_look_for_keys?: boolean;
  ssh_password?: string | null;
  created_at: string;
}

interface Scan {
  id: number;
  status: string;
  profile: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

interface ScanAssetStatusRow {
  asset_id: number;
  status: string;
  attempts: number;
  last_error?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

interface Finding {
  id: number;
  scan_id: number;
  asset_id: number;
  host_address?: string | null;
  host_os_name?: string | null;
  host_os_accuracy?: string | null;
  host_vendor?: string | null;
  traceroute_summary?: string | null;
  host_report?: string | null;
  port?: number | null;
  protocol?: string | null;
  service_name?: string | null;
  cve_ids?: string | null;
  severity: string;
  status: string;
  description?: string | null;
  detected_at: string;
  cvss_v31_base?: number | null;
  cvss_vector?: string | null;
  references?: string[] | null;
}

interface FindingEnrichment {
  cpe?: string | null;
  cvss_v31_base?: number | null;
  cvss_vector?: string | null;
  references?: string[] | null;
  last_enriched_at?: string | null;
  source?: string | null;
}

interface Integration {
  id: number;
  name: string;
  status: 'connected' | 'pending' | 'error' | 'disabled';
  lastSync?: string | null;
  mode?: string | null;
  notes?: string | null;
}

const SCAN_PROFILES = [
  { key: 'quick', label: 'Quick Scan' },
  { key: 'quick_plus', label: 'Quick Scan Plus' },
  { key: 'quick_traceroute', label: 'Quick Traceroute' },
  { key: 'ping', label: 'Ping Scan' },
  { key: 'regular', label: 'Regular Scan' },
  { key: 'all_tcp_ports', label: 'All TCP Ports' },
  { key: 'common_tcp_connect', label: 'Common TCP Connect' },
  { key: 'common_tcp_syn', label: 'Common TCP SYN' },
  { key: 'common_tcp_version', label: 'Common TCP Version' },
  { key: 'honeypot_version_demo', label: 'Honeypot Version Demo' },
  { key: 'intense', label: 'Intense Scan' },
  { key: 'intense_all_tcp', label: 'Intense Scan (All TCP)' },
  { key: 'intense_no_ping', label: 'Intense Scan (No Ping)' },
  { key: 'intense_udp', label: 'Intense Scan + UDP' },
  { key: 'slow_comprehensive', label: 'Slow Comprehensive' },
  { key: 'random_telnet_open', label: 'Random Telnet (10 hosts)' },
  { key: 'telnet_internet_random', label: 'Telnet Internet Random (100 hosts)' },
];

const STATUS_COLORS: Record<string, string> = {
  queued: 'yellow',
  running: 'indigo',
  completed: 'teal',
  completed_with_errors: 'orange',
  failed: 'red',
  cancelled: 'gray',
};

const SEVERITY_COLORS: Record<string, string> = {
  informational: 'gray',
  low: 'teal',
  medium: 'yellow',
  high: 'orange',
  critical: 'red',
};

const INTEGRATION_STATUS_COLORS: Record<Integration['status'], string> = {
  connected: 'teal',
  pending: 'yellow',
  error: 'red',
  disabled: 'gray',
};

const TABLE_HEIGHT = 420;
const TABLE_HEIGHT_MOBILE = 320;
const SUMMARY_TILE_HEIGHT = 160;
const SUMMARY_TILE_HEIGHT_MOBILE = 140;
const SUMMARY_CARD_HEIGHT = 200;
const SUMMARY_CARD_HEIGHT_MOBILE = 180;
const SUMMARY_CARD_BODY_HEIGHT = 120;

const api = axios.create({ baseURL: API_BASE, timeout: 15000 });

// Attach bearer token if present and auto-refresh on 401s
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('clanker_access_token');
  if (token) {
    config.headers = config.headers || {};
    (config.headers as any)['Authorization'] = `Bearer ${token}`;
  }
  return config;
});
let _isRefreshing = false;
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config || {};
    if (error?.response?.status === 401 && !original._retry) {
      if (_isRefreshing) throw error;
      original._retry = true;
      _isRefreshing = true;
      try {
        const refresh = localStorage.getItem('clanker_refresh_token');
        if (!refresh) throw error;
        const r = await api.post('/auth/refresh', { refresh_token: refresh });
        localStorage.setItem('clanker_access_token', r.data.access_token);
        localStorage.setItem('clanker_refresh_token', r.data.refresh_token);
        original.headers = original.headers || {};
        original.headers['Authorization'] = `Bearer ${r.data.access_token}`;
        return api(original);
      } finally {
        _isRefreshing = false;
      }
    }
    throw error;
  },
);

const parseApiError = (error: unknown): { message: string; status?: number } => {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;
    const data = error.response?.data as any;
    const detail = typeof data?.detail === 'string' ? data.detail : undefined;
    const message = detail || (typeof data?.message === 'string' ? data.message : error.message);
    return { message: message || 'Unexpected error', status };
  }
  if (error instanceof Error) {
    return { message: error.message };
  }
  return { message: 'Unexpected error' };
};

const glassStyles = {
  background: 'rgba(10, 15, 28, 0.72)',
  border: '1px solid rgba(99,102,241,0.12)',
  backdropFilter: 'blur(18px)',
};

const hostCardStyles = {
  background: 'linear-gradient(135deg, rgba(8,11,20,0.92), rgba(17,24,39,0.85))',
  border: '1px solid rgba(99,102,241,0.18)',
  boxShadow: '0 25px 40px rgba(2,6,23,0.6)',
};

const gradientCard = (gradient: string) => ({
  background: gradient,
  border: '1px solid rgba(255,255,255,0.1)',
  boxShadow: '0 20px 40px rgba(0,0,0,0.3)',
});

function StatusBadge({ status }: { status: string }) {
  return <Badge color={STATUS_COLORS[status] || 'gray'}>{status.replaceAll('_', ' ')}</Badge>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  return <Badge color={SEVERITY_COLORS[normalized] || 'gray'}>{severity}</Badge>;
}

function App() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [findingFilter, setFindingFilter] = useState<'all' | 'low' | 'medium' | 'high' | 'critical'>('all');
  const [findingSearch, setFindingSearch] = useState('');
  const [findingSort, setFindingSort] = useState<'recent' | 'severity' | 'port'>('recent');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedFindingEnrichment, setSelectedFindingEnrichment] = useState<FindingEnrichment | null>(null);
  const [findingGroupLimit] = useState(8);
  const [scanFilter, setScanFilter] = useState<'all' | 'queued' | 'running' | 'completed' | 'failed' | 'completed_with_errors'>('all');
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [scanEvents, setScanEvents] = useState<Array<{ id: number; created_at: string; message: string }>>([]);
  const [eventsAutoRefresh, setEventsAutoRefresh] = useState(true);
  const [assetStatuses, setAssetStatuses] = useState<ScanAssetStatusRow[]>([]);
  const [currentUser, setCurrentUser] = useState<{ email: string; role: string; name?: string | null } | null>(null);
  const canWrite = !!currentUser && ['admin', 'operator'].includes(currentUser.role);
  const [menuOpen, setMenuOpen] = useState<boolean>(false);
  const [authChecked, setAuthChecked] = useState<boolean>(false);
  const path = typeof window !== 'undefined' ? window.location.pathname.toLowerCase() : '';
  const isLoginPage = path.endsWith('/app/login') || path.endsWith('/login');
  const isLogoutPage = path.endsWith('/app/logout') || path.endsWith('/logout');
  const [isMobile, setIsMobile] = useState<boolean>(false);

  const [assetForm, setAssetForm] = useState({
    name: '',
    target: '',
    environment: '',
    owner: '',
    notes: '',
    credentialed: false,
    ssh_username: '',
    ssh_port: '22',
    ssh_auth_method: 'password',
    ssh_key_path: '',
    ssh_allow_agent: false,
    ssh_look_for_keys: false,
    ssh_password: '',
  });
  const [editingAssetId, setEditingAssetId] = useState<number | null>(null);
  const [scanForm, setScanForm] = useState({ profile: 'intense' });
  const [selectedAssetIds, setSelectedAssetIds] = useState<string[]>([]);

  const [assetsTotal, setAssetsTotal] = useState<number>(0);
  const [scansTotal, setScansTotal] = useState<number>(0);
  const [findingsTotal, setFindingsTotal] = useState<number>(0);
  const pageSize = 100;
  const [assetsOffset, setAssetsOffset] = useState(0);
  const [scansOffset, setScansOffset] = useState(0);
  const [findingsOffset, setFindingsOffset] = useState(0);
  const [activeTab, setActiveTab] = useState<'assets' | 'scans' | 'findings' | 'schedules' | 'integrations' | 'reports'>('assets');
  const [loginOpen, setLoginOpen] = useState<boolean>(false);
  const [loginEmail, setLoginEmail] = useState<string>('');
  const [loginPassword, setLoginPassword] = useState<string>('');
  const [usersOpen, setUsersOpen] = useState<boolean>(false);
  const [users, setUsers] = useState<Array<{ id: number; email: string; name?: string | null; role: string; active: boolean; created_at: string }>>([]);
  const [newUser, setNewUser] = useState<{ email: string; name: string; role: 'admin' | 'operator' | 'viewer'; password: string }>({ email: '', name: '', role: 'operator', password: '' });
  const [profileOpen, setProfileOpen] = useState<boolean>(false);
  const [profileName, setProfileName] = useState<string>('');
  const [changePwOpen, setChangePwOpen] = useState<boolean>(false);
  const [oldPw, setOldPw] = useState<string>('');
  const [newPw, setNewPw] = useState<string>('');
  const [auditOpen, setAuditOpen] = useState<boolean>(false);
  const [auditRows, setAuditRows] = useState<Array<{ id: number; created_at: string; actor_user_id?: number | null; action: string; target?: string | null; ip?: string | null; detail?: string | null }>>([]);
  const [auditFilter, setAuditFilter] = useState<{ user_id?: string; action?: string; since?: string; until?: string }>({});
  const selectedScan = useMemo(() => scans.find((s) => s.id === selectedScanId) ?? null, [selectedScanId, scans]);
  type Schedule = {
    id: number;
    name: string;
    profile: string;
    active: boolean;
    assetIds: number[];
    daysOfWeek: number[];
    times: string[];
    last_run_at?: string | null;
    next_run_at?: string | null;
  };
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [scheduleModalOpen, setScheduleModalOpen] = useState<boolean>(false);
  const [editingScheduleId, setEditingScheduleId] = useState<number | null>(null);
  const [scheduleForm, setScheduleForm] = useState<{ name: string; profile: string; assetIds: string[]; active: boolean; daysOfWeek: string[]; times: string[] }>({
    name: '',
    profile: 'intense',
    assetIds: [],
    active: true,
    daysOfWeek: ['0', '1', '2', '3', '4'], // weekdays by default
    times: ['09:00'],
  });
  const [scheduleTimesText, setScheduleTimesText] = useState<string>('09:00');
  const [scheduleError, setScheduleError] = useState<string>('');
  const findingsFetchedOnce = useRef(false);

  const refreshAll = async () => {
    setLoading(true);
    try {
      const [assetRes, scanRes] = await Promise.all([
        api.get<Asset[]>('/assets', { params: { limit: pageSize, offset: 0 } }),
        api.get<Scan[]>('/scans', { params: { limit: pageSize, offset: 0, status: scanFilter === 'all' ? undefined : scanFilter } }),
      ]);
      setAssets(assetRes.data);
      setScans(scanRes.data);
      setAssetsTotal(parseTotalCount(assetRes.headers as Record<string, unknown>, assetRes.data.length));
      setScansTotal(parseTotalCount(scanRes.headers as Record<string, unknown>, scanRes.data.length));
      setAssetsOffset(assetRes.data.length);
      setScansOffset(scanRes.data.length);
      await refreshFindings(0, false);
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to load data', message: `${error}` });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshAll();
  }, []);

  useEffect(() => {
    const update = () => setIsMobile(typeof window !== 'undefined' && window.innerWidth < 768);
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);

  useEffect(() => {
    // Attempt to populate current user if tokens exist; otherwise show login modal (unless on login/logout pages)
    const token = localStorage.getItem('clanker_access_token');
    if (!token) {
      setCurrentUser(null);
      if (!isLoginPage && !isLogoutPage) setLoginOpen(true);
      setAuthChecked(true);
      return;
    }
    api.get('/auth/me')
      .then((r) => { setCurrentUser({ email: r.data.email, role: r.data.role, name: r.data.name }); setProfileName(r.data.name || ''); })
      .catch(() => {
        setCurrentUser(null);
        localStorage.removeItem('clanker_access_token');
        localStorage.removeItem('clanker_refresh_token');
        if (!isLoginPage && !isLogoutPage) setLoginOpen(true);
      })
      .finally(() => setAuthChecked(true));
  }, []);

  useEffect(() => {
    if (activeTab === 'schedules' && currentUser && currentUser.role !== 'admin') {
      setActiveTab('assets');
    }
  }, [activeTab, currentUser?.role]);

  useEffect(() => {
    const loadExt = async () => {
      if (!selectedFinding) { setSelectedFindingEnrichment(null); return; }
      const fallback = deriveEnrichmentFromFinding(selectedFinding);
      try {
        const res = await api.get(`/finding_ext/${selectedFinding.id}`);
        const enriched = normalizeEnrichment(res.data?.enrichment);
        setSelectedFindingEnrichment(enriched ?? fallback);
      } catch (e) {
        setSelectedFindingEnrichment(fallback);
      }
    };
    loadExt();
  }, [selectedFinding?.id]);

useEffect(() => {
  if (!autoRefresh) return undefined;
  const interval = setInterval(refreshAll, 120000);
  return () => clearInterval(interval);
}, [autoRefresh]);

useEffect(() => {
  if (!findingsFetchedOnce.current) {
    findingsFetchedOnce.current = true;
    return;
  }
  refreshFindings(0, false);
}, [findingFilter, findingSearch]);

const resetAssetForm = () => {
  setAssetForm({
    name: '',
    target: '',
    environment: '',
    owner: '',
    notes: '',
    credentialed: false,
    ssh_username: '',
    ssh_port: '22',
    ssh_auth_method: 'password',
    ssh_key_path: '',
    ssh_allow_agent: false,
    ssh_look_for_keys: false,
    ssh_password: '',
  });
  setEditingAssetId(null);
};

const parseTotalCount = (headers: Record<string, unknown>, fallback: number): number => {
  const raw = headers['x-total-count'] as string | undefined;
  const parsed = raw ? parseInt(raw, 10) : NaN;
  return Number.isNaN(parsed) ? fallback : parsed;
};

const buildFindingsParams = (offsetValue: number) => ({
  limit: pageSize,
  offset: offsetValue,
  severity: findingFilter === 'all' ? undefined : findingFilter,
  q: findingSearch.trim() ? findingSearch.trim() : undefined,
});

const refreshFindings = async (offsetValue = 0, append = false) => {
  try {
    const res = await api.get<Finding[]>('/findings', { params: buildFindingsParams(offsetValue) });
    const total = parseTotalCount(res.headers as Record<string, unknown>, res.data.length);
    if (append) {
      setFindings((prev) => prev.concat(res.data));
      setFindingsOffset((o) => o + res.data.length);
    } else {
      setFindings(res.data);
      setFindingsOffset(res.data.length);
    }
    setFindingsTotal(total);
  } catch (error) {
    notifications.show({ color: 'red', title: 'Failed to load findings', message: `${error}` });
  }
};

const handleLogout = async (): Promise<void> => {
  try {
    await api.post('/auth/logout', { revoke_all: true });
  } catch (_) {
    // ignore network/auth errors on logout
    }
    localStorage.removeItem('clanker_access_token');
    localStorage.removeItem('clanker_refresh_token');
    setCurrentUser(null);
    notifications.show({ color: 'green', title: 'Logged out', message: 'Your session has been cleared' });
    setMenuOpen(false);
  };

  const handleLogin = async (): Promise<void> => {
    try {
      const r = await api.post('/auth/login', { email: loginEmail, password: loginPassword });
      localStorage.setItem('clanker_access_token', r.data.access_token);
      localStorage.setItem('clanker_refresh_token', r.data.refresh_token);
      const me = await api.get('/auth/me');
      setCurrentUser({ email: me.data.email, role: me.data.role, name: me.data.name });
      notifications.show({ color: 'green', title: 'Logged in', message: me.data.email });
      setLoginOpen(false);
      setMenuOpen(false);
    } catch (e) {
      const { message, status } = parseApiError(e);
      const title = status === 429 ? 'Too many attempts' : 'Login failed';
      notifications.show({ color: 'red', title, message });
    }
  };

  // Dedicated Login/Logout pages (no router dependency)
  // Handle logout as a side effect to keep hooks order consistent
  useEffect(() => {
    if (!isLogoutPage) return;
    (async () => {
      try { await api.post('/auth/logout', { revoke_all: true }); } catch {}
      localStorage.removeItem('clanker_access_token');
      localStorage.removeItem('clanker_refresh_token');
      setCurrentUser(null);
      notifications.show({ color: 'green', title: 'Logged out', message: 'Goodbye!' });
      setTimeout(() => { window.location.assign('/app/'); }, 800);
    })();
  }, [isLogoutPage]);

  // Stream scan events (hooks must be declared before any early returns)
  useEffect(() => {
    if (selectedScanId == null) return () => {};
    let es: EventSource | null = null;
    const open = () => {
      try {
        es = new EventSource(`${API_BASE || ''}/scans/${selectedScanId}/events/stream`);
        es.onmessage = (ev) => {
          try {
            const payload = JSON.parse(ev.data);
            setScanEvents((prev) => {
              if (!prev.find((p) => p.id === payload.id)) {
                return [payload, ...prev].slice(0, 200);
              }
              return prev;
            });
          } catch {}
        };
        es.onerror = () => {
          if (es) {
            es.close();
            es = null;
            setTimeout(() => open(), 2000);
          }
        };
      } catch {}
    };
    if (eventsAutoRefresh) open();
    return () => { if (es) es.close(); };
  }, [selectedScanId, eventsAutoRefresh]);

  useEffect(() => {
    if (selectedScanId == null) {
      setScanEvents([]);
      setAssetStatuses([]);
      return;
    }
    let cancelled = false;
    const loadScanDetails = async () => {
      try {
        const [eventsRes, assetsRes] = await Promise.all([
          api.get(`/scans/${selectedScanId}/events`),
          api.get(`/scans/${selectedScanId}/assets`),
        ]);
        if (cancelled) return;
        setScanEvents(eventsRes.data);
        setAssetStatuses(assetsRes.data);
      } catch (error) {
        if (!cancelled) {
          notifications.show({ color: 'red', title: 'Failed to load scan details', message: `${error}` });
        }
      }
    };
    loadScanDetails();
    return () => {
      cancelled = true;
    };
  }, [selectedScanId]);

  // Note: Do not early-return before declaring hooks. Auth/login views are
  // returned later to preserve consistent hook order across renders.
  const handleAssetSubmit = async () => {
    try {
      if (assetForm.credentialed) {
        if (!assetForm.ssh_username.trim()) {
          notifications.show({ color: 'yellow', title: 'Username required', message: 'Provide an SSH username' });
          return;
        }
        const hasPassword = assetForm.ssh_auth_method === 'password' && assetForm.ssh_password.trim().length > 0;
        const hasKey = assetForm.ssh_auth_method === 'key' && assetForm.ssh_key_path.trim().length > 0;
        const hasAgent = assetForm.ssh_auth_method === 'agent' && (assetForm.ssh_allow_agent || assetForm.ssh_look_for_keys);
        if (!hasPassword && !hasKey && !hasAgent) {
          notifications.show({ color: 'yellow', title: 'Credential missing', message: 'Add a password, key path, or enable agent/key discovery' });
          return;
        }
      }
      const payload = {
        name: assetForm.name || null,
        target: assetForm.target,
        environment: assetForm.environment || null,
        owner: assetForm.owner || null,
        notes: assetForm.notes || null,
        credentialed: assetForm.credentialed,
        ssh_username: assetForm.credentialed ? assetForm.ssh_username || null : null,
        ssh_port: assetForm.credentialed ? parseInt(assetForm.ssh_port, 10) || 22 : null,
        ssh_auth_method: assetForm.credentialed ? assetForm.ssh_auth_method : null,
        ssh_key_path: assetForm.credentialed ? assetForm.ssh_key_path || null : null,
        ssh_allow_agent: assetForm.credentialed ? assetForm.ssh_allow_agent : false,
        ssh_look_for_keys: assetForm.credentialed ? assetForm.ssh_look_for_keys : false,
        ssh_password: assetForm.credentialed ? assetForm.ssh_password || null : null,
      };
      if (editingAssetId != null) {
        await api.patch(`/assets/${editingAssetId}`, payload);
        notifications.show({ color: 'green', title: 'Asset updated', message: assetForm.target });
      } else {
        await api.post('/assets', payload);
        notifications.show({ color: 'green', title: 'Asset added', message: assetForm.target });
      }
      resetAssetForm();
      refreshAll();
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to save asset', message: `${error}` });
    }
  };

  const handleAssetEdit = (asset: Asset) => {
    setEditingAssetId(asset.id);
    setAssetForm({
      name: asset.name ?? '',
      target: asset.target,
      environment: asset.environment ?? '',
      owner: asset.owner ?? '',
      notes: asset.notes ?? '',
      credentialed: Boolean(asset.credentialed),
      ssh_username: asset.ssh_username ?? '',
      ssh_port: asset.ssh_port ? String(asset.ssh_port) : '22',
      ssh_auth_method: asset.ssh_auth_method ?? 'password',
      ssh_key_path: asset.ssh_key_path ?? '',
      ssh_allow_agent: Boolean(asset.ssh_allow_agent),
      ssh_look_for_keys: Boolean(asset.ssh_look_for_keys),
      ssh_password: asset.ssh_password ?? '',
    });
  };

  const runCredentialedScan = async (asset: Asset) => {
    try {
      await api.post(`/assets/${asset.id}/ssh_scan`);
      notifications.show({ color: 'green', title: 'Credentialed scan queued', message: asset.target });
    } catch (error) {
      notifications.show({ color: 'red', title: 'SSH scan failed', message: `${error}` });
    }
  };

  const handleScanSubmit = async () => {
    const assetIds = selectedAssetIds.map((value) => parseInt(value, 10)).filter((value) => !Number.isNaN(value));
    if (assetIds.length === 0) {
      notifications.show({ color: 'yellow', title: 'Provide asset IDs', message: 'Add at least one asset ID' });
      return;
    }
    // Validate that selected IDs still exist in the current asset list
    const available = new Set(assets.map((a) => a.id));
    const validIds = assetIds.filter((id) => available.has(id));
    const missing = assetIds.filter((id) => !available.has(id));
    if (missing.length > 0) {
      if (validIds.length === 0) {
        notifications.show({ color: 'yellow', title: 'Assets no longer available', message: 'Selected assets were removed. Please re-select from the list.' });
        setSelectedAssetIds([]);
        return;
      }
      notifications.show({ color: 'yellow', title: 'Some assets missing', message: `Removed IDs: ${missing.join(', ')}. Proceeding with remaining ${validIds.length}.` });
    }
    // Ensure profile is valid
    const allowedProfiles = new Set(SCAN_PROFILES.map((p) => p.key));
    const profileKey = allowedProfiles.has(scanForm.profile) ? scanForm.profile : 'intense';
    try {
      await api.post('/scans', { asset_ids: validIds, profile: profileKey });
      notifications.show({ color: 'green', title: 'Scan queued', message: `${assetIds.length} asset(s)` });
      setSelectedAssetIds([]);
      refreshAll();
    } catch (error) {
      const err: any = error;
      const status = err?.response?.status;
      const detail = err?.response?.data?.detail;
      if (status === 404 && typeof detail === 'string') {
        notifications.show({ color: 'red', title: 'Failed to queue scan', message: detail.includes('assets') ? 'One or more selected assets no longer exist. Please re-select.' : detail });
      } else if (status === 400 && typeof detail === 'string') {
        notifications.show({ color: 'red', title: 'Invalid request', message: detail });
      } else {
        notifications.show({ color: 'red', title: 'Failed to queue scan', message: `${error}` });
      }
    }
  };

  const handleScanCancel = async (scanId: number) => {
    try {
      const res = await api.post<Scan>(`/scans/${scanId}/cancel`);
      const updated = res.data;
      setScans((prev) => {
        let found = false;
        const mapped = prev.map((scan) => {
          if (scan.id === scanId) {
            found = true;
            return { ...scan, ...updated };
          }
          return scan;
        });
        return found ? mapped : mapped.concat(updated);
      });
      if (selectedScanId === scanId) {
        const [eventsRes, assetsRes] = await Promise.allSettled([
          api.get(`/scans/${scanId}/events`),
          api.get(`/scans/${scanId}/assets`),
        ]);
        if (eventsRes.status === 'fulfilled') setScanEvents(eventsRes.value.data);
        if (assetsRes.status === 'fulfilled') setAssetStatuses(assetsRes.value.data);
      }
      notifications.show({ color: 'yellow', title: 'Scan cancelled', message: `Scan #${scanId}` });
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to cancel', message: `${error}` });
    }
  };

  const handleAssetDelete = async (assetId: number) => {
    try {
      await api.delete(`/assets/${assetId}`);
      notifications.show({ color: 'green', title: 'Asset removed', message: `Asset #${assetId}` });
      refreshAll();
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to remove asset', message: `${error}` });
    }
  };

  const handleScanDelete = async (scanId: number) => {
    try {
      await api.delete(`/scans/${scanId}`);
      notifications.show({ color: 'green', title: 'Scan removed', message: `Scan #${scanId}` });
      refreshAll();
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to remove scan', message: `${error}` });
    }
  };

  const scanStatusSummary = useMemo(() => {
    return scans.reduce<Record<string, number>>((acc, scan) => {
      acc[scan.status] = (acc[scan.status] ?? 0) + 1;
      return acc;
    }, {});
  }, [scans]);

  const severitySummary = useMemo(() => {
    return findings.reduce<Record<string, number>>((acc, finding) => {
      const key = finding.severity.toLowerCase();
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
  }, [findings]);

  const openFindings = useMemo(() => findings.filter((finding) => finding.status.toLowerCase() === 'open').length, [findings]);
  const activeScans = (scanStatusSummary.running ?? 0) + (scanStatusSummary.queued ?? 0);
  const integrations = useMemo<Integration[]>(() => [
    {
      id: 1,
      name: 'CVE Enrichment (NVD mirror)',
      status: 'connected',
      mode: 'Enrichment',
      lastSync: '5 minutes ago',
      notes: 'Pulls CVSS, CWE, and references for new findings.',
    },
    {
      id: 2,
      name: 'Jira Cloud',
      status: 'pending',
      mode: 'Ticketing',
      lastSync: null,
      notes: 'Waiting for project + API token.',
    },
    {
      id: 3,
      name: 'Slack Webhook',
      status: 'error',
      mode: 'Notifications',
      lastSync: '2 hours ago',
      notes: 'Recent delivery failed signature verification.',
    },
    {
      id: 4,
      name: 'ServiceNow',
      status: 'disabled',
      mode: 'Ticketing',
      lastSync: null,
      notes: 'Enable when change management sign-off is ready.',
    },
  ], []);

  const severityRingData = Object.entries(severitySummary).map(([severity, count]) => ({
    value: count,
    color: SEVERITY_COLORS[severity] || 'gray',
    tooltip: `${severity.toUpperCase()}: ${count}`,
  }));
  const totalSeverityCount = Object.values(severitySummary).reduce((acc, val) => acc + val, 0);
  const severityProgressSections = severityRingData.length
    ? severityRingData.map(({ value, color }) => ({
        value: totalSeverityCount > 0 ? (value / totalSeverityCount) * 100 : 0,
        color,
      }))
    : [{ value: 100, color: '#334155' }];

  const assetLookup = useMemo(() => {
    const map = new Map<number, Asset>();
    assets.forEach((asset) => map.set(asset.id, asset));
    return map;
  }, [assets]);

  const filteredFindings = useMemo(() => {
    let list = findings;
    if (findingFilter !== 'all') {
      list = list.filter((f) => f.severity.toLowerCase() === findingFilter);
    }
    if (findingSearch.trim()) {
      const q = findingSearch.trim().toLowerCase();
      list = list.filter((f) =>
        (f.service_name || '').toLowerCase().includes(q) ||
        (f.host_address || '').toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q)
      );
    }
    return list;
  }, [findings, findingFilter, findingSearch]);

  const surfaces = useMemo(() => {
    const isLight = colorScheme === 'light';
    return {
      glass: isLight
        ? {
            background: 'rgba(255, 255, 255, 0.75)',
            border: '1px solid rgba(15, 23, 42, 0.08)',
            backdropFilter: 'blur(14px)',
          }
        : glassStyles,
      host: isLight
        ? {
            background: 'linear-gradient(135deg, rgba(248,250,252,0.95), rgba(241,245,249,0.9))',
            border: '1px solid rgba(2,6,23,0.06)',
            boxShadow: '0 12px 24px rgba(2,6,23,0.08)',
          }
        : hostCardStyles,
      accent: (from: string, to: string) =>
        isLight
          ? {
              background: `linear-gradient(135deg, ${from}, ${to})`,
              border: '1px solid rgba(2,6,23,0.06)',
              boxShadow: '0 12px 28px rgba(2,6,23,0.08)',
            }
          : gradientCard(`linear-gradient(135deg, ${from}, ${to})`),
      tile: isLight
        ? {
            background: '#ffffff',
            border: '1px solid rgba(2,6,23,0.06)',
            boxShadow: '0 12px 28px rgba(2,6,23,0.08)',
          }
        : undefined,
    } as const;
  }, [colorScheme]);

  const findingsByHost = useMemo(() => {
    const groups = new Map<string, {
      hostLabel: string;
      assetName?: string;
      hostOsName?: string | null;
      hostOsAccuracy?: string | null;
      hostVendor?: string | null;
      tracerouteSummary?: string | null;
      hostReport?: string | null;
      findings: Finding[];
    }>();
    filteredFindings.forEach((finding) => {
      const asset = assetLookup.get(finding.asset_id);
      const hostLabel = finding.host_address || asset?.target || `Asset #${finding.asset_id}`;
      const key = `${hostLabel}-${finding.asset_id}`;
      if (!groups.has(key)) {
        groups.set(key, {
          hostLabel,
          assetName: asset?.name ?? undefined,
          hostOsName: finding.host_os_name ?? null,
          hostOsAccuracy: finding.host_os_accuracy ?? null,
          hostVendor: finding.host_vendor ?? null,
          tracerouteSummary: finding.traceroute_summary ?? null,
          hostReport: finding.host_report ?? null,
          findings: [],
        });
      } else {
        const entry = groups.get(key)!;
        if (!entry.hostOsName && finding.host_os_name) {
          entry.hostOsName = finding.host_os_name;
          entry.hostOsAccuracy = finding.host_os_accuracy ?? entry.hostOsAccuracy;
        }
        if (!entry.hostVendor && finding.host_vendor) {
          entry.hostVendor = finding.host_vendor;
        }
        if (!entry.tracerouteSummary && finding.traceroute_summary) {
          entry.tracerouteSummary = finding.traceroute_summary;
        }
        if (!entry.hostReport && finding.host_report) {
          entry.hostReport = finding.host_report;
        }
      }
      groups.get(key)!.findings.push(finding);
    });
    return Array.from(groups.values());
  }, [filteredFindings, assetLookup]);

  const findingGroupIndex = useMemo(() => {
    const map = new Map<number, { hostLabel: string; hostReport?: string | null }>();
    findingsByHost.forEach((group) => {
      group.findings.forEach((f) => map.set(f.id, { hostLabel: group.hostLabel, hostReport: group.hostReport }));
    });
    return map;
  }, [findingsByHost]);

  const parseCves = (value?: string | null): string[] => {
    if (!value) return [];
    try {
      const data = JSON.parse(value);
      return Array.isArray(data) ? data.filter((s) => typeof s === 'string') : [];
    } catch {
      // Fall back: single CVE id inline
      if (typeof value === 'string' && value.toUpperCase().includes('CVE-')) return [value];
      return [];
    }
  };

  const normalizeEnrichment = (value: any): FindingEnrichment | null => {
    if (!value) return null;
    let references: string[] = [];
    if (Array.isArray(value.references)) {
      references = value.references.filter((r: unknown) => typeof r === 'string');
    } else if (typeof value.references_json === 'string') {
      try {
        const parsed = JSON.parse(value.references_json);
        if (Array.isArray(parsed)) references = parsed.filter((r: unknown) => typeof r === 'string');
      } catch {
        // ignore parsing errors
      }
    }
    const normalized: FindingEnrichment = {
      cpe: value.cpe ?? null,
      cvss_v31_base: value.cvss_v31_base ?? null,
      cvss_vector: value.cvss_vector ?? null,
      references,
      last_enriched_at: value.last_enriched_at ?? null,
      source: value.source ?? null,
    };
    const hasData = normalized.cvss_v31_base != null || !!normalized.cvss_vector || !!normalized.cpe || (references && references.length > 0);
    return hasData ? normalized : null;
  };

  const deriveEnrichmentFromFinding = (finding?: Finding | null): FindingEnrichment | null => {
    if (!finding) return null;
    return normalizeEnrichment({
      cvss_v31_base: finding.cvss_v31_base,
      cvss_vector: finding.cvss_vector,
      references: finding.references,
    });
  };

  const displayedEnrichment = useMemo(
    () => selectedFindingEnrichment ?? deriveEnrichmentFromFinding(selectedFinding),
    [selectedFindingEnrichment, selectedFinding],
  );

  const canCancelScan = (status?: string | null) => {
    if (!status) return false;
    return !['completed', 'failed', 'completed_with_errors', 'cancelled'].includes(status);
  };

  const filteredScans = useMemo(() => {
    return scanFilter === 'all' ? scans : scans.filter((s) => s.status === scanFilter);
  }, [scans, scanFilter]);

  const visibleScans = filteredScans;
  const visibleAssets = assets;

  const exportCsv = (rows: Array<Record<string, unknown>>, filename: string) => {
    if (!rows.length) return;
    const keys = Array.from(rows.reduce<Set<string>>((acc, r) => { Object.keys(r).forEach((k) => acc.add(k)); return acc; }, new Set()));
    const csv = [keys.join(',')]
      .concat(rows.map((row) => keys.map((k) => {
          const v = (row as any)[k];
          const s = v == null ? '' : String(v).replaceAll('"', '""');
          return `"${s}` + '"';
        }).join(',')))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportJson = (rows: unknown[], filename: string) => {
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportFindings = async (format: 'csv' | 'json') => {
    try {
      const params = { ...buildFindingsParams(0), format };
      const res = await api.get(`/reports/findings/export`, {
        params,
        responseType: format === 'csv' ? 'blob' : 'json',
      });
      if (format === 'csv') {
        const blob = new Blob([res.data], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'findings.csv';
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const payload = (res.data as any)?.rows ?? res.data;
        exportJson(Array.isArray(payload) ? payload : [payload], 'findings.json');
      }
      const headerBands = (res.headers as Record<string, unknown>)['x-cvss-bands'];
      const bandSummary = typeof headerBands === 'string' ? JSON.parse(headerBands) : res.data?.cvss_bands;
      if (bandSummary) {
        notifications.show({
          color: 'teal',
          title: 'CVSS band summary',
          message: `Critical ${bandSummary.critical ?? 0} · High ${bandSummary.high ?? 0} · Medium ${bandSummary.medium ?? 0}`,
        });
      }
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to export findings', message: `${e}` });
    }
  };

  const dayOptions = [
    { label: 'Mon', value: '0' },
    { label: 'Tue', value: '1' },
    { label: 'Wed', value: '2' },
    { label: 'Thu', value: '3' },
    { label: 'Fri', value: '4' },
    { label: 'Sat', value: '5' },
    { label: 'Sun', value: '6' },
  ];

  const parseTimesInput = (raw: string): string[] => {
    return raw
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  };

  const isValidTime = (t: string): boolean => {
    if (!t.includes(':')) return false;
    const [hStr, mStr] = t.split(':');
    const h = Number(hStr);
    const m = Number(mStr);
    return Number.isInteger(h) && Number.isInteger(m) && h >= 0 && h <= 23 && m >= 0 && m <= 59;
  };

  const resetScheduleForm = () => {
    setEditingScheduleId(null);
    setScheduleForm({ name: '', profile: 'intense', assetIds: [], active: true, daysOfWeek: ['0', '1', '2', '3', '4'], times: ['09:00'] });
    setScheduleTimesText('09:00');
    setScheduleError('');
  };

  const handleSaveSchedule = async () => {
    setScheduleError('');
    if (!scheduleForm.name.trim()) {
      setScheduleError('Name is required');
      return;
    }
    if (scheduleForm.daysOfWeek.length === 0) {
      setScheduleError('Select at least one day');
      return;
    }
    const times = scheduleForm.times.filter((t) => t.trim().length > 0);
    if (times.length === 0) {
      setScheduleError('Add at least one time');
      return;
    }
    const invalidTimes = times.filter((t) => !isValidTime(t));
    if (invalidTimes.length > 0) {
      setScheduleError(`Invalid time(s): ${invalidTimes.join(', ')}`);
      return;
    }
    const assetIds = scheduleForm.assetIds.map((v) => parseInt(v, 10)).filter((v) => !Number.isNaN(v));
    if (assetIds.length === 0) {
      setScheduleError('Select at least one asset');
      return;
    }
    const payload = {
      name: scheduleForm.name,
      profile: scheduleForm.profile,
      asset_ids: assetIds,
      days_of_week: scheduleForm.daysOfWeek.map((d) => parseInt(d, 10)),
      times: times,
      active: scheduleForm.active,
    };
    try {
      if (editingScheduleId) {
        await api.patch(`/schedules/${editingScheduleId}`, payload);
        notifications.show({ color: 'green', title: 'Schedule updated', message: scheduleForm.name });
      } else {
        await api.post('/schedules', payload);
        notifications.show({ color: 'green', title: 'Schedule created', message: scheduleForm.name });
      }
      setScheduleModalOpen(false);
      resetScheduleForm();
      loadSchedules();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to save schedule', message: `${e}` });
    }
  };

  const handleEditSchedule = (sch: Schedule) => {
    setEditingScheduleId(sch.id);
    setScheduleForm({
      name: sch.name,
      profile: sch.profile,
      assetIds: sch.assetIds.map((id) => String(id)),
      active: sch.active,
      daysOfWeek: sch.daysOfWeek.map((d) => String(d)),
      times: sch.times,
    });
    setScheduleTimesText(sch.times.join(', '));
    setScheduleModalOpen(true);
  };

  const handleToggleSchedule = async (sch: Schedule) => {
    try {
      await api.patch(`/schedules/${sch.id}`, { active: !sch.active });
      notifications.show({ color: 'green', title: sch.active ? 'Schedule paused' : 'Schedule resumed', message: sch.name });
      loadSchedules();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to toggle schedule', message: `${e}` });
    }
  };

  const handleRunNow = async (sch: Schedule) => {
    try {
      await api.post(`/schedules/${sch.id}/run-now`);
      notifications.show({ color: 'green', title: 'Run queued', message: sch.name });
      loadSchedules();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to run schedule', message: `${e}` });
    }
  };

  const handleDeleteSchedule = async (sch: Schedule) => {
    if (!window.confirm(`Delete schedule "${sch.name}"?`)) return;
    try {
      await api.delete(`/schedules/${sch.id}`);
      notifications.show({ color: 'green', title: 'Schedule deleted', message: sch.name });
      loadSchedules();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to delete schedule', message: `${e}` });
    }
  };

  const parseAssetIds = (raw: unknown): number[] => {
    if (Array.isArray(raw)) {
      return raw.map((v) => parseInt(String(v), 10)).filter((v) => !Number.isNaN(v));
    }
    if (typeof raw === 'string') {
      try {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          return arr.map((v) => parseInt(String(v), 10)).filter((v) => !Number.isNaN(v));
        }
      } catch {}
    }
    return [];
  };

  const loadSchedules = async () => {
    if (!currentUser || currentUser.role !== 'admin') return;
    try {
      const res = await api.get('/schedules');
      const mapped = res.data.map((s: any) => ({
        id: s.id,
        name: s.name,
        profile: s.profile,
        active: s.active,
        assetIds: parseAssetIds(s.asset_ids ?? s.asset_ids_json ?? []),
        daysOfWeek: Array.isArray(s.days_of_week) ? s.days_of_week.map((d: any) => parseInt(String(d), 10)).filter((n: number) => !Number.isNaN(n)) : [],
        times: Array.isArray(s.times) ? s.times.map((t: any) => String(t)) : [],
        last_run_at: s.last_run_at ?? null,
        next_run_at: s.next_run_at ?? null,
      }));
      setSchedules(mapped);
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to load schedules', message: `${e}` });
    }
  };

  useEffect(() => {
    if (activeTab === 'schedules') loadSchedules();
  }, [activeTab, currentUser?.role]);

  

  // Auth/login gates placed after hooks to preserve order
  if (isLogoutPage) {
    return (
      <AppShell padding="lg" styles={{ main: { background: 'transparent' } }}>
        <AppShell.Main>
          <Stack align="center" justify="center" style={{ minHeight: '70vh' }}>
            <Title order={3} c={colorScheme === 'light' ? '#0b1220' : undefined}>Signing you out…</Title>
            <Text c="dimmed">Redirecting to home</Text>
          </Stack>
        </AppShell.Main>
      </AppShell>
    );
  }

  if (isLoginPage) {
    return (
      <AppShell padding="lg" styles={{ main: { background: 'transparent' } }}>
        <AppShell.Main>
          <Stack align="center" justify="center" style={{ minHeight: '70vh' }}>
            <Card padding="xl" radius="md" shadow="xl" style={colorScheme === 'light' ? { background: 'white' } : glassStyles}>
              <Stack w={360}>
                <Group justify="center">
                  <ThemeIcon
                    size={56}
                    radius="xl"
                    variant="gradient"
                    gradient={{ from: 'red', to: 'grape' }}
                    style={{ boxShadow: '0 12px 24px rgba(239,68,68,0.35)' }}
                  >
                    <IconRobot size={26} />
                  </ThemeIcon>
                </Group>
                <Title order={3} c={colorScheme === 'light' ? '#0b1220' : undefined}>Sign in</Title>
                <TextInput label="Email" placeholder="you@example.com" value={loginEmail} onChange={(e) => setLoginEmail(e.currentTarget.value)} />
                <PasswordInput label="Password" placeholder="••••••••" value={loginPassword} onChange={(e) => setLoginPassword(e.currentTarget.value)} />
                <Group justify="space-between">
                  <Button variant="light" component="a" href="/app/">Back</Button>
                  <Button onClick={async () => { await handleLogin(); if (localStorage.getItem('clanker_access_token')) window.location.assign('/app/'); }} leftSection={<IconSend size={14} />}>Login</Button>
                </Group>
              </Stack>
            </Card>
          </Stack>
        </AppShell.Main>
      </AppShell>
    );
  }

  if (!authChecked) {
    return (
      <AppShell padding="lg" styles={{ main: { background: 'transparent' } }}>
        <AppShell.Main>
          <Stack align="center" justify="center" style={{ minHeight: '70vh' }}>
            <Loader color="indigo" />
            <Text c="dimmed">Checking authentication…</Text>
          </Stack>
        </AppShell.Main>
      </AppShell>
    );
  }

  if (!currentUser) {
    return (
      <AppShell padding="lg" styles={{ main: { background: 'transparent' } }}>
        <AppShell.Main>
          <Stack align="center" justify="center" style={{ minHeight: '70vh' }}>
            <Card padding="xl" radius="md" shadow="xl" style={colorScheme === 'light' ? { background: 'white' } : glassStyles}>
              <Stack w={360}>
                <Group justify="center">
                  <ThemeIcon
                    size={56}
                    radius="xl"
                    variant="gradient"
                    gradient={{ from: 'red', to: 'grape' }}
                    style={{ boxShadow: '0 12px 24px rgba(239,68,68,0.35)' }}
                  >
                    <IconRobot size={26} />
                  </ThemeIcon>
                </Group>
                <Title order={3} c={colorScheme === 'light' ? '#0b1220' : undefined}>Sign in</Title>
                <TextInput label="Email" placeholder="you@example.com" value={loginEmail} onChange={(e) => setLoginEmail(e.currentTarget.value)} />
                <PasswordInput label="Password" placeholder="••••••••" value={loginPassword} onChange={(e) => setLoginPassword(e.currentTarget.value)} />
                <Group justify="flex-end">
                  <Button onClick={async () => { await handleLogin(); if (localStorage.getItem('clanker_access_token')) window.location.assign('/app/'); }} leftSection={<IconSend size={14} />}>Login</Button>
                </Group>
              </Stack>
            </Card>
          </Stack>
        </AppShell.Main>
      </AppShell>
    );
  }

  return (
    <AppShell padding="lg" header={{ height: 70 }} styles={{ main: { background: 'transparent' } }}>
      <AppShell.Header style={{ background: 'rgba(5,8,15,0.7)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <Stack gap="sm" px="lg" py="sm">
          <Group gap="md" align="center" justify="flex-start" wrap="wrap">
            <Group gap="md" align="center" wrap="wrap">
              <Burger opened={menuOpen} onClick={() => setMenuOpen((v) => !v)} size="sm" aria-label="Open menu" />
              <ThemeIcon
                size={48}
                radius="xl"
                variant="gradient"
                gradient={{ from: 'red', to: 'grape' }}
                style={{ boxShadow: '0 15px 30px rgba(239,68,68,0.45)' }}
              >
                <IconRobot size={24} />
              </ThemeIcon>
              <div>
                <Text
                  component="h1"
                  fw={700}
                  size="xl"
                  style={{
                    background: 'linear-gradient(120deg, #60a5fa, #a78bfa)',
                    WebkitBackgroundClip: 'text',
                    color: 'transparent',
                    margin: 0,
                  }}
                >
                  Clanker Command Console
                </Text>
                <Text
                  size="md"
                  fw={600}
                  c={colorScheme === 'light' ? '#0b1220' : '#e5e7eb'}
                  style={{ letterSpacing: 0.2, textShadow: colorScheme === 'light' ? 'none' : '0 1px 2px rgba(0,0,0,0.45)' }}
                >
                  Network awareness & vulnerability visibility
                </Text>
              </div>
            </Group>
            <Group gap="sm" align="center" style={{ marginLeft: 'auto' }}>
              <Group gap="sm" align="center">
                <Badge
                  color={autoRefresh ? 'green' : 'gray'}
                  variant="light"
                  radius="xl"
                  leftSection={<IconClockHour4 size={14} />}
                  onClick={() => setAutoRefresh((prev) => !prev)}
                  style={{ cursor: 'pointer' }}
                >
                  Auto refresh: {autoRefresh ? 'ON' : 'OFF'}
                </Badge>
                <Badge color={activeScans > 0 ? 'indigo' : 'gray'} variant="filled">
                  Active scans: {activeScans}
                </Badge>
              </Group>
              <Tooltip label="Refresh data now">
                <Button rightSection={<IconRefresh size={16} />} variant="gradient" gradient={{ from: 'indigo', to: 'cyan' }} onClick={refreshAll} loading={loading}>
                  Refresh
                </Button>
              </Tooltip>
            </Group>
          </Group>
          <Drawer opened={menuOpen} onClose={() => setMenuOpen(false)} position="left" size="xs" title="Menu">
            <Stack>
              {currentUser ? (
                <>
                  <Group gap="xs">
                    <ThemeIcon variant="light" color="indigo"><IconUser size={16} /></ThemeIcon>
                    <div>
                      <Text fw={600} size="sm">{currentUser.name || currentUser.email}</Text>
                      <Text size="xs" c="dimmed">Role: {currentUser.role}</Text>
                    </div>
                  </Group>
                  <Divider />
            <Button fullWidth variant="light" onClick={() => { setActiveTab('assets'); setMenuOpen(false); }}>Assets</Button>
            <Button fullWidth variant="light" onClick={() => { setActiveTab('scans'); setMenuOpen(false); }}>Scans</Button>
            <Button fullWidth variant="light" onClick={() => { setActiveTab('findings'); setMenuOpen(false); }}>Findings</Button>
            <Button fullWidth variant="light" onClick={() => { setProfileName(currentUser?.name || ''); setProfileOpen(true); }}>My Profile</Button>
            <Button fullWidth variant="light" onClick={() => setChangePwOpen(true)}>Change Password</Button>
            {currentUser.role === 'admin' && (
              <>
                <Button fullWidth variant="light" onClick={() => setUsersOpen(true)}>Users</Button>
                <Button fullWidth variant="light" onClick={async () => { try { setAuditOpen(true); const r = await api.get('/audit_logs'); setAuditRows(r.data); } catch (e) { notifications.show({ color: 'red', title: 'Failed to load audit logs', message: `${e}` }); } }}>Audit Logs</Button>
              </>
            )}
                  <Button fullWidth variant="light" onClick={() => setColorScheme(colorScheme === 'light' ? 'dark' : 'light')}>
                    Switch to {colorScheme === 'light' ? 'dark' : 'light'} mode
                  </Button>
                  <Divider />
                  <Button fullWidth variant="light" color="red" leftSection={<IconLogout size={16} />} onClick={handleLogout}>Logout</Button>
                </>
              ) : (
                <>
                  <Text c="dimmed">Not signed in</Text>
                  <Group gap="xs">
                    <Button fullWidth onClick={() => setLoginOpen(true)}>Login</Button>
                    <Button fullWidth variant="subtle" component="a" href="/app/login">Login page</Button>
                  </Group>
                </>
              )}
            </Stack>
          </Drawer>
          <Group gap="sm" justify="space-between" wrap="wrap">
            <Group gap="sm" wrap="wrap">
              <ActionIcon
                variant="subtle"
                size="lg"
                aria-label="Toggle color scheme"
                onClick={() => setColorScheme(colorScheme === 'light' ? 'dark' : 'light')}
                title={colorScheme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
              />
            </Group>
          </Group>
        </Stack>
      </AppShell.Header>
      <Modal opened={loginOpen} onClose={() => setLoginOpen(false)} title="Sign in" centered>
        <Stack>
          <TextInput label="Email" placeholder="you@example.com" value={loginEmail} onChange={(e) => setLoginEmail(e.currentTarget.value)} />
          <PasswordInput label="Password" placeholder="••••••••" value={loginPassword} onChange={(e) => setLoginPassword(e.currentTarget.value)} />
          <Button onClick={handleLogin} leftSection={<IconSend size={14} />}>Login</Button>
        </Stack>
      </Modal>
      <Modal opened={usersOpen} onClose={() => setUsersOpen(false)} title="Users" size="lg" fullScreen={isMobile} centered>
        <Stack>
          <Group grow>
            <TextInput label="Email" value={newUser.email} onChange={(e) => setNewUser((p) => ({ ...p, email: e.currentTarget.value }))} />
            <TextInput label="Name" value={newUser.name} onChange={(e) => setNewUser((p) => ({ ...p, name: e.currentTarget.value }))} />
          </Group>
          <Group grow>
            <Select label="Role" data={[{ value: 'admin', label: 'Admin' }, { value: 'operator', label: 'Operator' }, { value: 'viewer', label: 'Viewer' }]} value={newUser.role} onChange={(v) => setNewUser((p) => ({ ...p, role: (v as any) || 'operator' }))} />
            <PasswordInput label="Password" value={newUser.password} onChange={(e) => setNewUser((p) => ({ ...p, password: e.currentTarget.value }))} />
          </Group>
          <Group justify="flex-end">
            <Button
              onClick={async () => {
                try {
                  await api.post('/users', { email: newUser.email, name: newUser.name || null, role: newUser.role, password: newUser.password });
                  const r = await api.get('/users');
                  setUsers(r.data);
                  setNewUser({ email: '', name: '', role: 'operator', password: '' });
                  notifications.show({ color: 'green', title: 'User created', message: 'User added' });
                } catch (e) {
                  notifications.show({ color: 'red', title: 'Failed to create user', message: `${e}` });
                }
              }}
              disabled={!newUser.email || !newUser.password}
            >
              Add user
            </Button>
          </Group>
          <ScrollArea h={280} offsetScrollbars>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>ID</Table.Th>
                  <Table.Th>Email</Table.Th>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Role</Table.Th>
                  <Table.Th>Active</Table.Th>
                  <Table.Th>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {users.map((u) => (
                  <Table.Tr key={u.id}>
                    <Table.Td>{u.id}</Table.Td>
                    <Table.Td>{u.email}</Table.Td>
                    <Table.Td>{u.name || '-'}</Table.Td>
                    <Table.Td>{u.role}</Table.Td>
                    <Table.Td>{u.active ? 'yes' : 'no'}</Table.Td>
                    <Table.Td>
                      <Group gap="xs">
                        <Button size="xs" variant="light" onClick={async () => { try { await api.patch(`/users/${u.id}`, { role: u.role === 'viewer' ? 'operator' : 'viewer' }); const r = await api.get('/users'); setUsers(r.data); } catch (e) { notifications.show({ color: 'red', title: 'Failed to update role', message: `${e}` }); } }}>Toggle role</Button>
                        <Button size="xs" variant="light" onClick={async () => { try { await api.patch(`/users/${u.id}`, { active: !u.active }); const r = await api.get('/users'); setUsers(r.data); } catch (e) { notifications.show({ color: 'red', title: 'Failed to toggle active', message: `${e}` }); } }}>{u.active ? 'Disable' : 'Enable'}</Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
          <Group justify="flex-end">
            <Button variant="light" onClick={async () => { try { const r = await api.get('/users'); setUsers(r.data); } catch (e) { notifications.show({ color: 'red', title: 'Failed to load users', message: `${e}` }); } }}>Refresh</Button>
          </Group>
        </Stack>
      </Modal>
      <Modal opened={profileOpen} onClose={() => setProfileOpen(false)} title="My Profile" fullScreen={isMobile} centered>
        <Stack>
          <TextInput label="Name" value={profileName} onChange={(e) => setProfileName(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button onClick={async () => { try { await api.patch('/auth/me', { name: profileName || null }); setCurrentUser((u) => (u ? { ...u, name: profileName } : u)); notifications.show({ color: 'green', title: 'Profile updated', message: '' }); setProfileOpen(false); } catch (e) { notifications.show({ color: 'red', title: 'Failed to update profile', message: `${e}` }); } }}>Save</Button>
          </Group>
        </Stack>
      </Modal>
      <Modal opened={changePwOpen} onClose={() => setChangePwOpen(false)} title="Change Password" fullScreen={isMobile} centered>
        <Stack>
          <PasswordInput label="Current password" value={oldPw} onChange={(e) => setOldPw(e.currentTarget.value)} />
          <PasswordInput label="New password" value={newPw} onChange={(e) => setNewPw(e.currentTarget.value)} description="Min 10 chars with upper, lower, number, and symbol" />
          <Group justify="flex-end">
            <Button onClick={async () => { try { await api.post('/auth/change_password', { old_password: oldPw, new_password: newPw }); setOldPw(''); setNewPw(''); notifications.show({ color: 'green', title: 'Password changed', message: '' }); setChangePwOpen(false); } catch (e) { const { message, status } = parseApiError(e); const title = status === 429 ? 'Too many attempts' : 'Failed to change password'; notifications.show({ color: 'red', title, message }); } }} disabled={!oldPw || !newPw}>Update</Button>
          </Group>
        </Stack>
      </Modal>
      <Modal opened={auditOpen} onClose={() => setAuditOpen(false)} title="Audit Logs" size="lg" fullScreen={isMobile} centered>
        <Stack>
          <Group grow>
            <TextInput label="User ID" value={auditFilter.user_id || ''} onChange={(e) => setAuditFilter((p) => ({ ...p, user_id: e.currentTarget.value }))} />
            <TextInput label="Action" value={auditFilter.action || ''} onChange={(e) => setAuditFilter((p) => ({ ...p, action: e.currentTarget.value }))} />
          </Group>
          <Group grow>
            <TextInput label="Since (ISO)" value={auditFilter.since || ''} onChange={(e) => setAuditFilter((p) => ({ ...p, since: e.currentTarget.value }))} />
            <TextInput label="Until (ISO)" value={auditFilter.until || ''} onChange={(e) => setAuditFilter((p) => ({ ...p, until: e.currentTarget.value }))} />
          </Group>
          <Group justify="flex-end">
            <Button variant="light" onClick={async () => { try { const r = await api.get('/audit_logs', { params: { user_id: auditFilter.user_id || undefined, action: auditFilter.action || undefined, since: auditFilter.since || undefined, until: auditFilter.until || undefined } }); setAuditRows(r.data); } catch (e) { notifications.show({ color: 'red', title: 'Failed to load logs', message: `${e}` }); } }}>Search</Button>
          </Group>
          <ScrollArea h={300}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>ID</Table.Th>
                  <Table.Th>Time</Table.Th>
                  <Table.Th>Actor</Table.Th>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>Target</Table.Th>
                  <Table.Th>IP</Table.Th>
                  <Table.Th>Detail</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {auditRows.map((r) => (
                  <Table.Tr key={r.id}>
                    <Table.Td>{r.id}</Table.Td>
                    <Table.Td>{new Date(r.created_at).toLocaleString()}</Table.Td>
                    <Table.Td>{r.actor_user_id ?? '-'}</Table.Td>
                    <Table.Td>{r.action}</Table.Td>
                    <Table.Td>{r.target || '-'}</Table.Td>
                    <Table.Td>{r.ip || '-'}</Table.Td>
                    <Table.Td>{r.detail || '-'}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Stack>
      </Modal>
      <Modal opened={scheduleModalOpen} onClose={() => { setScheduleModalOpen(false); resetScheduleForm(); }} title={editingScheduleId ? 'Edit schedule' : 'New schedule'} size="lg" fullScreen={isMobile} centered>
        <Stack>
          <TextInput label="Name" value={scheduleForm.name} onChange={(e) => setScheduleForm((p) => ({ ...p, name: e.currentTarget.value }))} />
          <Group grow>
            <MultiSelect
              label="Days"
              data={dayOptions}
              value={scheduleForm.daysOfWeek}
              onChange={(vals) => setScheduleForm((p) => ({ ...p, daysOfWeek: vals }))}
              clearable
            />
            <TextInput
              label="Times (HH:MM, comma separated)"
              placeholder="09:00, 17:00"
              value={scheduleTimesText}
              onChange={(e) => {
                const raw = e.currentTarget.value;
                setScheduleTimesText(raw);
                setScheduleForm((p) => ({ ...p, times: parseTimesInput(raw) }));
              }}
            />
          </Group>
          <Select
            label="Profile"
            data={SCAN_PROFILES.map((profile) => ({ value: profile.key, label: profile.label }))}
            value={scheduleForm.profile}
            onChange={(value) => value && setScheduleForm((prev) => ({ ...prev, profile: value }))}
          />
          <MultiSelect
            label="Assets"
            placeholder={assets.length ? 'Select assets' : 'Add assets first'}
            data={assets.map((asset) => ({ value: String(asset.id), label: `${asset.name ? `${asset.name} · ` : ''}${asset.target} (#${asset.id})` }))}
            value={scheduleForm.assetIds}
            onChange={(vals) => setScheduleForm((p) => ({ ...p, assetIds: vals }))}
            searchable
            nothingFoundMessage="No assets"
          />
          <Switch label="Active" checked={scheduleForm.active} onChange={(e) => setScheduleForm((p) => ({ ...p, active: e.currentTarget.checked }))} />
          {scheduleError && <Text c="red">{scheduleError}</Text>}
          <Group justify="flex-end">
            <Button variant="light" onClick={() => { resetScheduleForm(); setScheduleModalOpen(false); }}>Cancel</Button>
            <Button onClick={handleSaveSchedule}>{editingScheduleId ? 'Update' : 'Create'}</Button>
          </Group>
        </Stack>
      </Modal>
      <AppShell.Main>
        <Stack gap="lg">
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 4 }} spacing={{ base: 'sm', sm: 'md', lg: 'lg' }}>
            {(() => {
              const isLight = colorScheme === 'light';
              const tiles = [
                {
                  label: 'Assets',
                  value: assets.length,
                  icon: IconTarget,
                  subtitle: 'Managed hosts',
                  gradientDark: 'linear-gradient(135deg, rgba(129,230,217,0.35), rgba(79,70,229,0.25))',
                  gradientLight: 'linear-gradient(135deg, rgba(99,102,241,0.30), rgba(34,211,238,0.22))',
                  iconGradientDark: { from: 'cyan', to: 'indigo' },
                  iconGradientLight: { from: 'indigo', to: 'cyan' },
                },
                {
                  label: 'Active scans',
                  value: activeScans,
                  icon: IconRadar2,
                  subtitle: 'Queued / running',
                  gradientDark: 'linear-gradient(135deg, rgba(59,130,246,0.35), rgba(14,165,233,0.25))',
                  gradientLight: 'linear-gradient(135deg, rgba(79,70,229,0.30), rgba(59,130,246,0.24))',
                  iconGradientDark: { from: 'blue', to: 'teal' },
                  iconGradientLight: { from: 'indigo', to: 'blue' },
                },
                {
                  label: 'Open findings',
                  value: openFindings,
                  icon: IconAlertTriangle,
                  subtitle: 'Remediation backlog',
                  gradientDark: 'linear-gradient(135deg, rgba(252,165,165,0.35), rgba(234,88,12,0.3))',
                  gradientLight: 'linear-gradient(135deg, rgba(251,146,60,0.30), rgba(239,68,68,0.28))',
                  iconGradientDark: { from: 'orange', to: 'red' },
                  iconGradientLight: { from: 'orange', to: 'red' },
                },
                {
                  label: 'Total findings',
                  value: findings.length,
                  icon: IconSparkles,
                  subtitle: 'Captured issues',
                  gradientDark: 'linear-gradient(135deg, rgba(248,250,252,0.2), rgba(148,163,184,0.2))',
                  gradientLight: 'linear-gradient(135deg, rgba(167,139,250,0.26), rgba(99,102,241,0.22))',
                  iconGradientDark: { from: 'grape', to: 'pink' },
                  iconGradientLight: { from: 'violet', to: 'indigo' },
                },
              ];
              return tiles.map((card) => (
                <Card
                  key={card.label}
                  padding="lg"
                  style={{
                    ...(isLight ? (surfaces.tile as React.CSSProperties) : gradientCard(card.gradientDark)),
                    height: isMobile ? SUMMARY_TILE_HEIGHT_MOBILE : SUMMARY_TILE_HEIGHT,
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                  }}
                  radius="md"
                  shadow="xl"
                >
                  <Group justify="space-between" mb="xs">
                    <Text c={isLight ? '#1f2937' : 'gray.2'} size="sm" fw={600}>
                      {card.label}
                    </Text>
                    <ThemeIcon
                      variant="gradient"
                      gradient={isLight ? card.iconGradientLight : card.iconGradientDark}
                      radius="xl"
                      size="lg"
                    >
                      <card.icon size={18} />
                    </ThemeIcon>
                  </Group>
                  <Title order={2} c={isLight ? '#0b1220' : undefined}>{card.value}</Title>
                  <Text size="sm" c={isLight ? '#334155' : 'gray.4'}>
                    {card.subtitle}
                  </Text>
                </Card>
              ));
            })()}
          </SimpleGrid>

          <Grid>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Card
                padding="lg"
                radius="md"
                style={{
                  ...(colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles),
                  height: isMobile ? SUMMARY_CARD_HEIGHT_MOBILE : SUMMARY_CARD_HEIGHT,
                }}
                shadow="xl"
              >
                <Group justify="space-between" mb="md">
                  <div>
                    <Title order={4} c={colorScheme === 'light' ? '#0b1220' : undefined}>Scan status</Title>
                    <Text size="sm" c={colorScheme === 'light' ? '#334155' : 'dimmed'}>
                      Lifecycle snapshot
                    </Text>
                  </div>
                  <Group gap="xs">
                    {(scans.some((s) => s.status === 'running' || s.status === 'queued')) && (
                      <Badge variant="filled" color="blue">Active</Badge>
                    )}
                    <ThemeIcon variant="light" color="blue">
                      <IconShieldCheck size={18} />
                    </ThemeIcon>
                  </Group>
                </Group>
                <ScrollArea h={SUMMARY_CARD_BODY_HEIGHT} offsetScrollbars>
                  <Stack gap="xs">
                    {Object.keys(scanStatusSummary).length === 0 && <Text c="dimmed">No scans yet.</Text>}
                    {Object.entries(scanStatusSummary).map(([status, count]) => (
                      <Paper key={status} withBorder p="sm" radius="md" style={surfaces.glass}>
                        <Stack gap={6}>
                          <Group justify="space-between">
                            <StatusBadge status={status} />
                            <Text fw={600}>{count}</Text>
                          </Group>
                          <Progress
                            className="animate-progress"
                            value={Math.min(100, (count / Math.max(scans.length, 1)) * 100)}
                            w="100%"
                            color={STATUS_COLORS[status] || 'gray'}
                            striped={status === 'running' || status === 'queued'}
                            animated={status === 'running' || status === 'queued'}
                          />
                        </Stack>
                      </Paper>
                    ))}
                  </Stack>
                </ScrollArea>
              </Card>
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Card
                padding="lg"
                radius="md"
                style={{
                  ...(colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles),
                  height: isMobile ? SUMMARY_CARD_HEIGHT_MOBILE : SUMMARY_CARD_HEIGHT,
                }}
                shadow="xl"
              >
                <Group justify="space-between" mb="md">
                  <div>
                    <Title order={4} c={colorScheme === 'light' ? '#0b1220' : undefined}>Findings by severity</Title>
                    <Text size="sm" c={colorScheme === 'light' ? '#334155' : 'dimmed'}>
                      Distribution of latest scan results
                    </Text>
                  </div>
                </Group>
                <Stack gap="md" align="stretch">
                  <Stack gap={4} w="100%" align="stretch">
                    <Text size="sm" c="gray.6" ta="right" w="100%">
                      Total findings: {findings.length}
                    </Text>
                    <Progress.Root size="lg" radius="xl" w="100%">
                      {severityProgressSections.map(({ value, color }, idx) => (
                        <Progress.Section key={idx} value={value} color={color} />
                      ))}
                    </Progress.Root>
                  </Stack>
                  <Stack gap="xs" w="100%">
                    {Object.entries(severitySummary)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([severity, count]) => (
                        <Group key={severity} justify="space-between">
                          <SeverityBadge severity={severity} />
                          <Text fw={600}>{count}</Text>
                        </Group>
                      ))}
                  </Stack>
                </Stack>
              </Card>
            </Grid.Col>
          </Grid>

          <Tabs value={activeTab} onChange={(v) => setActiveTab((v as any) || 'assets')} radius="md" variant="pills">
            <Tabs.List style={{ background: colorScheme === 'light' ? 'rgba(2,6,23,0.06)' : 'rgba(15,23,42,0.6)', borderRadius: 999, padding: 4 }}>
              <Tabs.Tab value="assets">Assets</Tabs.Tab>
              <Tabs.Tab value="scans">Scans</Tabs.Tab>
              <Tabs.Tab value="findings">Findings</Tabs.Tab>
              {currentUser?.role === 'admin' && <Tabs.Tab value="schedules">Schedules</Tabs.Tab>}
              <Tabs.Tab value="integrations">Integrations</Tabs.Tab>
              <Tabs.Tab value="reports">Reports</Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel value="integrations" pt="sm">
              <Card padding="lg" radius="md" shadow="xl" style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles}>
                <Stack gap="md">
                  <Group justify="space-between" align="flex-start">
                    <div>
                      <Title order={4}>Integrations</Title>
                      <Text c="dimmed" size="sm">Connect enrichers, ticketing, and notifications. Configure credentials and webhooks here.</Text>
                    </div>
                    <Badge color="indigo" variant="light">Preview</Badge>
                  </Group>
                  <Table verticalSpacing="sm" horizontalSpacing="md">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Integration</Table.Th>
                        <Table.Th>Status</Table.Th>
                        <Table.Th>Mode</Table.Th>
                        <Table.Th>Last sync</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {integrations.map((integration) => (
                        <Table.Tr key={integration.id}>
                          <Table.Td>
                            <Group gap="sm">
                              <ThemeIcon variant="light" color="indigo" radius="md">
                                <IconPlugConnected size={16} />
                              </ThemeIcon>
                              <div>
                                <Text fw={600}>{integration.name}</Text>
                                {integration.notes && <Text size="xs" c="dimmed">{integration.notes}</Text>}
                              </div>
                            </Group>
                          </Table.Td>
                          <Table.Td>
                            <Badge color={INTEGRATION_STATUS_COLORS[integration.status]} variant="light" radius="sm">
                              {integration.status.charAt(0).toUpperCase() + integration.status.slice(1)}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm">{integration.mode || '—'}</Text>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm" c="dimmed">{integration.lastSync || 'Not synced yet'}</Text>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Stack>
              </Card>
            </Tabs.Panel>

            <Tabs.Panel value="reports" pt="sm">
              <Card padding="lg" radius="md" shadow="xl" style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles}>
                <Title order={4}>Reports</Title>
                <Text c="dimmed" size="sm">Coming soon: rollups and exports.</Text>
              </Card>
            </Tabs.Panel>

            <Tabs.Panel value="assets" pt="sm">
              <Grid gutter={{ base: 'md', md: 'xl' }}>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Card
                    padding="lg"
                    radius="md"
                    style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles}
                    shadow="xl"
                  >
                    <Group justify="space-between" mb="sm">
                      <Title order={4} c={colorScheme === 'light' ? '#0b1220' : undefined}>
                        {editingAssetId != null ? `Edit asset #${editingAssetId}` : 'Add asset'}
                      </Title>
                      {editingAssetId != null && (
                        <Button size="xs" variant="light" color="gray" onClick={resetAssetForm}>
                          Cancel
                        </Button>
                      )}
                    </Group>
                    <Stack>
                      <TextInput label="Name" value={assetForm.name} onChange={(event) => setAssetForm((prev) => ({ ...prev, name: event.currentTarget.value }))} />
                      <TextInput
                        required
                        label="Target"
                        placeholder="10.0.0.10 or web01.lan"
                        value={assetForm.target}
                        onChange={(event) => setAssetForm((prev) => ({ ...prev, target: event.currentTarget.value }))}
                      />
                      <TextInput label="Environment" placeholder="prod, staging" value={assetForm.environment} onChange={(event) => setAssetForm((prev) => ({ ...prev, environment: event.currentTarget.value }))} />
                      <TextInput label="Owner" value={assetForm.owner} onChange={(event) => setAssetForm((prev) => ({ ...prev, owner: event.currentTarget.value }))} />
                        <Textarea label="Notes" minRows={2} value={assetForm.notes} onChange={(event) => setAssetForm((prev) => ({ ...prev, notes: event.currentTarget.value }))} />
                        <Paper withBorder p="sm" radius="md">
                          <Group justify="space-between" mb="xs">
                            <div>
                              <Text fw={600}>Credentialed SSH</Text>
                              <Text size="xs" c="dimmed">Attach credentials so scans can pull OS/packages/services.</Text>
                            </div>
                            <Switch
                              checked={assetForm.credentialed}
                              onChange={(e) => setAssetForm((prev) => ({ ...prev, credentialed: e.currentTarget.checked }))}
                              label="Enable"
                            />
                          </Group>
                          {assetForm.credentialed && (
                            <Stack gap="xs">
                              <Group grow>
                                <TextInput
                                  label="Username"
                                  required
                                  value={assetForm.ssh_username}
                                  onChange={(e) => setAssetForm((prev) => ({ ...prev, ssh_username: e.currentTarget.value }))}
                                />
                                <TextInput
                                  label="Port"
                                  value={assetForm.ssh_port}
                                  onChange={(e) => setAssetForm((prev) => ({ ...prev, ssh_port: e.currentTarget.value }))}
                                  type="number"
                                />
                              </Group>
                              <SegmentedControl
                                fullWidth
                                value={assetForm.ssh_auth_method}
                                onChange={(v) => setAssetForm((prev) => ({ ...prev, ssh_auth_method: v }))}
                                data={[
                                  { label: 'Password', value: 'password' },
                                  { label: 'SSH key', value: 'key' },
                                  { label: 'Agent', value: 'agent' },
                                ]}
                              />
                              {assetForm.ssh_auth_method === 'password' && (
                                <PasswordInput
                                  label="Password"
                                  placeholder="Stored only for credentialed scans"
                                  value={assetForm.ssh_password}
                                  onChange={(e) => setAssetForm((prev) => ({ ...prev, ssh_password: e.currentTarget.value }))}
                                />
                              )}
                              {assetForm.ssh_auth_method === 'key' && (
                                <TextInput
                                  label="Private key path"
                                  placeholder="/home/audit/.ssh/id_rsa"
                                  value={assetForm.ssh_key_path}
                                  onChange={(e) => setAssetForm((prev) => ({ ...prev, ssh_key_path: e.currentTarget.value }))}
                                />
                              )}
                              {assetForm.ssh_auth_method === 'agent' && (
                                <Group>
                                  <Switch
                                    label="Use ssh-agent"
                                    checked={assetForm.ssh_allow_agent}
                                    onChange={(e) => setAssetForm((prev) => ({ ...prev, ssh_allow_agent: e.currentTarget.checked }))}
                                  />
                                  <Switch
                                    label="Discover keys on host"
                                    checked={assetForm.ssh_look_for_keys}
                                    onChange={(e) => setAssetForm((prev) => ({ ...prev, ssh_look_for_keys: e.currentTarget.checked }))}
                                  />
                                </Group>
                              )}
                            </Stack>
                          )}
                        </Paper>
                      <Button leftSection={<IconSend size={16} />} onClick={handleAssetSubmit} disabled={!assetForm.target.trim()}>
                        {editingAssetId != null ? 'Update asset' : 'Save asset'}
                      </Button>
                    </Stack>
                  </Card>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 8 }}>
                  <Card padding="lg" radius="md" style={surfaces.glass} shadow="xl">
                    <Group justify="space-between" mb="xs">
                      <Group gap="xs">
                        <Badge variant="light">{assets.length} total</Badge>
                        <Button variant="light" onClick={() => exportCsv(visibleAssets.map(a => ({ id: a.id, target: a.target, name: a.name, environment: a.environment, owner: a.owner, created_at: a.created_at })), 'assets.csv')}>Export CSV</Button>
                        <Button variant="light" onClick={() => exportJson(visibleAssets, 'assets.json')}>Export JSON</Button>
                      </Group>
                    </Group>
                      <Group justify="space-between" mb="sm">
                        <Group gap="xs">
                          <Title order={4} c={colorScheme === 'light' ? '#0b1220' : undefined}>Assets</Title>
                          <Badge variant="filled" color="indigo">{assets.length}</Badge>
                        </Group>
                      </Group>
                    <ScrollArea h={isMobile ? TABLE_HEIGHT_MOBILE : TABLE_HEIGHT} offsetScrollbars>
                      <Table highlightOnHover verticalSpacing="sm" striped>
                        <Table.Thead>
                          <Table.Tr>
                            <Table.Th>ID</Table.Th>
                            <Table.Th>Target</Table.Th>
                            <Table.Th>Name</Table.Th>
                            <Table.Th>Environment</Table.Th>
                            <Table.Th>Owner</Table.Th>
                            <Table.Th>Actions</Table.Th>
                          </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                          {visibleAssets.map((asset) => (
                            <Table.Tr key={asset.id}>
                              <Table.Td>{asset.id}</Table.Td>
                              <Table.Td>
                                <Stack gap={2}>
                                  <Text>{asset.target}</Text>
                                  <Group gap={4}>
                                    {asset.credentialed && <Badge size="xs" color="indigo" variant="light">Credentialed</Badge>}
                                    {asset.environment && <Badge size="xs" variant="light">{asset.environment}</Badge>}
                                  </Group>
                                </Stack>
                              </Table.Td>
                              <Table.Td>{asset.name || '-'}</Table.Td>
                              <Table.Td>{asset.environment || '-'}</Table.Td>
                              <Table.Td>{asset.owner || '-'}</Table.Td>
                              <Table.Td>
                                <Group gap="xs">
                                  <Button size="xs" variant="light" onClick={() => handleAssetEdit(asset)} disabled={!canWrite}>
                                    Edit
                                  </Button>
                                  {asset.credentialed && (
                                    <Button size="xs" variant="light" color="indigo" onClick={() => runCredentialedScan(asset)} disabled={!canWrite}>
                                      Run credentialed
                                    </Button>
                                  )}
                                  <Button size="xs" color="red" variant="light" onClick={() => handleAssetDelete(asset.id)} disabled={!canWrite}>
                                    Remove
                                  </Button>
                                </Group>
                              </Table.Td>
                            </Table.Tr>
                          ))}
                        </Table.Tbody>
                      </Table>
                    </ScrollArea>
                    {assetsOffset < assetsTotal && (
                      <Group justify="center" mt="xs">
                        <Button variant="light" onClick={async () => { await (async () => { try { const res = await api.get<Asset[]>('/assets', { params: { limit: pageSize, offset: assetsOffset } }); setAssets((prev) => prev.concat(res.data)); setAssetsOffset((o) => o + res.data.length); setAssetsTotal(parseInt((res.headers['x-total-count'] as any) ?? `${assetsTotal}`, 10) || assetsTotal); } catch (e) { notifications.show({ color: 'red', title: 'Failed to load more assets', message: `${e}` }); } })(); }}>Load more</Button>
                      </Group>
                    )}
                  </Card>
                </Grid.Col>
              </Grid>
            </Tabs.Panel>

            <Tabs.Panel value="scans" pt="sm">
              <Grid gutter={{ base: 'md', md: 'xl' }}>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Card padding="lg" radius="md" style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles} shadow="xl">
                    <Title order={5} mb="sm">
                      Queue scan
                    </Title>
                    <Stack>
                      <MultiSelect
                        label="Assets"
                        placeholder={assets.length ? 'Select assets' : 'Add assets first'}
                        data={assets.map((asset) => ({
                          value: String(asset.id),
                          label: `${asset.name ? `${asset.name} · ` : ''}${asset.target} (#${asset.id})`,
                        }))}
                        value={selectedAssetIds}
                        onChange={setSelectedAssetIds}
                        searchable
                        nothingFoundMessage="No assets"
                        disabled={assets.length === 0}
                      />
                      <Select
                        label="Profile"
                        data={SCAN_PROFILES.map((profile) => ({ value: profile.key, label: profile.label }))}
                        value={scanForm.profile}
                        onChange={(value) => value && setScanForm((prev) => ({ ...prev, profile: value }))}
                      />
                      <Button onClick={handleScanSubmit} disabled={!canWrite}>Start scan</Button>
                    </Stack>
                  </Card>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 8 }}>
                  <Card padding="lg" radius="md" style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles} shadow="xl">
                    <Group justify="space-between" mb="xs">
                      <Group gap="xs">
                        <SegmentedControl value={scanFilter} onChange={(v) => setScanFilter(v as typeof scanFilter)} data={[{ label: 'All', value: 'all' }, { label: 'Queued', value: 'queued' }, { label: 'Running', value: 'running' }, { label: 'Done', value: 'completed' }, { label: 'Failed', value: 'failed' }]} />
                        <Button variant="light" onClick={() => exportCsv(visibleScans.map(s => ({ id: s.id, status: s.status, profile: s.profile, created_at: s.created_at, started_at: s.started_at, completed_at: s.completed_at })), 'scans.csv')}>Export CSV</Button>
                        <Button variant="light" onClick={() => exportJson(visibleScans, 'scans.json')}>Export JSON</Button>
                      </Group>
                      <Badge variant="light">{scansTotal} total</Badge>
                    </Group>
                    <ScrollArea h={isMobile ? TABLE_HEIGHT_MOBILE : TABLE_HEIGHT} offsetScrollbars>
                      <Table highlightOnHover verticalSpacing="sm" striped>
                        <Table.Thead>
                          <Table.Tr>
                            <Table.Th>ID</Table.Th>
                            <Table.Th>Status</Table.Th>
                            <Table.Th>Profile</Table.Th>
                            <Table.Th>Created</Table.Th>
                            <Table.Th>Started</Table.Th>
                            <Table.Th>Completed</Table.Th>
                            <Table.Th>Actions</Table.Th>
                          </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                          {visibleScans.map((scan) => (
                            <Table.Tr key={scan.id}>
                              <Table.Td>{scan.id}</Table.Td>
                              <Table.Td>
                                <StatusBadge status={scan.status} />
                              </Table.Td>
                              <Table.Td>{scan.profile}</Table.Td>
                              <Table.Td>{new Date(scan.created_at).toLocaleString()}</Table.Td>
                              <Table.Td>{scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}</Table.Td>
                              <Table.Td>{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}</Table.Td>
                              <Table.Td>
                                <Group gap="xs">
                                  <Button size="xs" variant="light" onClick={() => setSelectedScanId(scan.id)}>
                                    View
                                  </Button>
                                  <Button size="xs" variant="light" color="orange" onClick={() => handleScanCancel(scan.id)} disabled={!canWrite || !canCancelScan(scan.status)}>
                                    Cancel
                                  </Button>
                                  <Button size="xs" color="red" variant="light" onClick={() => handleScanDelete(scan.id)}>
                                    Remove
                                  </Button>
                                </Group>
                              </Table.Td>
                            </Table.Tr>
                          ))}
                        </Table.Tbody>
                      </Table>
                    </ScrollArea>
                    {scansOffset < scansTotal && (
                      <Group justify="center" mt="xs">
                        <Button variant="light" onClick={async () => { try { const res = await api.get<Scan[]>('/scans', { params: { limit: pageSize, offset: scansOffset, status: scanFilter === 'all' ? undefined : scanFilter } }); setScans((prev) => prev.concat(res.data)); setScansOffset((o) => o + res.data.length); setScansTotal(parseInt((res.headers['x-total-count'] as any) ?? `${scansTotal}`, 10) || scansTotal); } catch (e) { notifications.show({ color: 'red', title: 'Failed to load more scans', message: `${e}` }); } }}>Load more</Button>
                      </Group>
                    )}
                  </Card>
                </Grid.Col>
              </Grid>
            </Tabs.Panel>

            <Tabs.Panel value="findings" pt="sm">
              <Card padding="lg" radius="md" style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles} shadow="xl">
                <Stack gap="sm" mb="md">
                  <Title order={5}>Findings</Title>
                  <Group gap="xs" wrap="wrap">
                    <SegmentedControl
                      value={findingFilter}
                      onChange={(value) => setFindingFilter(value as typeof findingFilter)}
                      data={[
                        { label: 'All', value: 'all' },
                        { label: 'Low', value: 'low' },
                        { label: 'Medium', value: 'medium' },
                        { label: 'High', value: 'high' },
                        { label: 'Critical', value: 'critical' },
                      ]}
                    />
                    <SegmentedControl
                      value={findingSort}
                      onChange={(v) => setFindingSort(v as typeof findingSort)}
                      data={[
                        { label: 'Recent', value: 'recent' },
                        { label: 'Severity', value: 'severity' },
                        { label: 'Port', value: 'port' },
                      ]}
                    />
                    <TextInput placeholder="Search service, host, text" value={findingSearch} onChange={(e) => setFindingSearch(e.currentTarget.value)} style={{ minWidth: rem(180), flex: 1 }} />
                    <Group gap="xs" wrap="wrap">
                      <Button variant="light" onClick={() => exportFindings('csv')}>Export CSV</Button>
                      <Button variant="light" onClick={() => exportFindings('json')}>Export JSON</Button>
                    </Group>
                  </Group>
                </Stack>
                <Stack gap="md">
                  {findingsByHost.length === 0 && <Text c="dimmed">No findings to summarize.</Text>}
                  {findingsByHost.slice(0, findingGroupLimit).map((group) => (
                    <Paper key={group.hostLabel} withBorder p="md" radius="md" style={surfaces.host}>
                      <Group justify="space-between" mb="xs">
                        <div>
                          <Text fw={600}>Nmap scan report for {group.hostLabel}</Text>
                          <Text size="sm" c="gray.5">
                            Asset: {group.assetName || 'unknown'} · Open ports: {group.findings.length}
                          </Text>
                        </div>
                        <Badge color="green" variant="filled" radius="sm">
                          Host up
                        </Badge>
                      </Group>
                      <Table striped highlightOnHover>
                        <Table.Thead>
                          <Table.Tr>
                            <Table.Th>PORT</Table.Th>
                            <Table.Th>SERVICE</Table.Th>
                            <Table.Th>SEVERITY</Table.Th>
                            <Table.Th>STATUS</Table.Th>
                            <Table.Th>DETECTED</Table.Th>
                          </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                          {group.findings
                            .sort((a, b) => {
                              if (findingSort === 'port') return (a.port ?? 0) - (b.port ?? 0);
                              if (findingSort === 'severity') {
                                const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
                                return (order[(b.severity || '').toLowerCase()] ?? 0) - (order[(a.severity || '').toLowerCase()] ?? 0);
                              }
                              // recent
                              return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime();
                            })
                            .map((finding) => (
                              <Table.Tr key={`${group.hostLabel}-${finding.id}`} onClick={() => setSelectedFinding(finding)} style={{ cursor: 'pointer' }}>
                                <Table.Td>{finding.port ? `${finding.port}/${finding.protocol || 'tcp'}` : '-'}</Table.Td>
                                <Table.Td>{finding.service_name || 'unknown'}</Table.Td>
                                <Table.Td>
                                  <SeverityBadge severity={finding.severity} />
                                </Table.Td>
                                <Table.Td>
                                  <StatusBadge status={finding.status} />
                                </Table.Td>
                                <Table.Td>{new Date(finding.detected_at).toLocaleString()}</Table.Td>
                              </Table.Tr>
                            ))}
                        </Table.Tbody>
                      </Table>
                      {group.hostReport && (
                        <Paper
                          mt="md"
                          p="md"
                          radius="md"
                          style={{
                            background: 'rgba(15,23,42,0.7)',
                            border: '1px solid rgba(148,163,184,0.25)',
                          }}
                        >
                          <Group justify="space-between" mb="sm">
                            <Text fw={600} size="sm" c={colorScheme === 'light' ? '#ffffff' : undefined}>
                              Intense scan details
                            </Text>
                            <Badge color="grape" variant="light">
                              Raw nmap output
                            </Badge>
                          </Group>
                          <ScrollArea h={220} offsetScrollbars>
                            <Text
                              component="pre"
                              style={{
                                whiteSpace: 'pre-wrap',
                                fontFamily: 'SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                                fontSize: '0.85rem',
                                lineHeight: 1.4,
                                color: colorScheme === 'light' ? '#ffffff' : undefined,
                              }}
                            >
                              {group.hostReport}
                            </Text>
                          </ScrollArea>
                        </Paper>
                      )}
                    </Paper>
                  ))}
                </Stack>
                {findingsOffset < findingsTotal && (
                  <Group justify="center" mt="md">
                    <Button
                      variant="light"
                      onClick={() => refreshFindings(findingsOffset, true)}
                    >
                      Load more
                    </Button>
                  </Group>
                )}
              </Card>
            </Tabs.Panel>

            {currentUser?.role === 'admin' && (
              <Tabs.Panel value="schedules" pt="sm">
                <Card padding="lg" radius="md" style={colorScheme === 'light' ? (surfaces.tile as React.CSSProperties) : glassStyles} shadow="xl">
                  <Group justify="space-between" mb="md">
                    <div>
                      <Title order={4} c={colorScheme === 'light' ? '#0b1220' : undefined}>Schedules</Title>
                      <Text size="sm" c={colorScheme === 'light' ? '#334155' : 'dimmed'}>Create recurring scans</Text>
                    </div>
                    <Group gap="xs">
                      <Button variant="light" onClick={() => loadSchedules()}>Refresh</Button>
                      <Button onClick={() => { resetScheduleForm(); setScheduleModalOpen(true); }}>New schedule</Button>
                    </Group>
                  </Group>
                  <ScrollArea h={isMobile ? TABLE_HEIGHT_MOBILE : TABLE_HEIGHT} offsetScrollbars>
                    <Table striped highlightOnHover>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Name</Table.Th>
                          <Table.Th>Days</Table.Th>
                          <Table.Th>Times</Table.Th>
                          <Table.Th>Profile</Table.Th>
                          <Table.Th>Assets</Table.Th>
                          <Table.Th>Active</Table.Th>
                          <Table.Th>Last run</Table.Th>
                          <Table.Th>Actions</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {schedules.map((sch) => (
                          <Table.Tr key={sch.id}>
                            <Table.Td>{sch.name}</Table.Td>
                            <Table.Td>
                              <Group gap={6}>
                                {(sch.daysOfWeek.length ? sch.daysOfWeek : [0, 1, 2, 3, 4, 5, 6]).map((d) => (
                                  <Badge key={d} variant="light">{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][d] ?? d}</Badge>
                                ))}
                              </Group>
                            </Table.Td>
                            <Table.Td>
                              <Group gap={6}>
                                {(sch.times.length ? sch.times : ['00:00']).map((t) => (
                                  <Badge key={t} color="blue" variant="outline">{t}</Badge>
                                ))}
                              </Group>
                            </Table.Td>
                            <Table.Td>{sch.profile}</Table.Td>
                            <Table.Td>{sch.assetIds.length}</Table.Td>
                            <Table.Td>
                              <Badge color={sch.active ? 'teal' : 'gray'}>{sch.active ? 'yes' : 'no'}</Badge>
                            </Table.Td>
                            <Table.Td>
                              <Stack gap={2}>
                                <Text size="sm">{sch.last_run_at ? new Date(sch.last_run_at).toLocaleString() : '-'}</Text>
                                <Text size="xs" c="dimmed">Next: {sch.next_run_at ? new Date(sch.next_run_at).toLocaleString() : '-'}</Text>
                              </Stack>
                            </Table.Td>
                            <Table.Td>
                            <Group gap="xs">
                              <Button size="xs" variant="light" onClick={() => handleEditSchedule(sch)}>Edit</Button>
                              <Button size="xs" variant="light" color={sch.active ? 'yellow' : 'teal'} onClick={() => handleToggleSchedule(sch)}>
                                {sch.active ? 'Pause' : 'Resume'}
                              </Button>
                              <Button size="xs" variant="light" color="green" onClick={() => handleRunNow(sch)}>Run now</Button>
                              <Button size="xs" variant="light" color="red" onClick={() => handleDeleteSchedule(sch)}>Delete</Button>
                            </Group>
                          </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </ScrollArea>
                  {schedules.length === 0 && <Text c="dimmed" mt="sm">No schedules yet.</Text>}
                </Card>
              </Tabs.Panel>
            )}
          </Tabs>
        </Stack>
      </AppShell.Main>
      <Drawer
        opened={selectedFinding != null}
        onClose={() => setSelectedFinding(null)}
        title={selectedFinding ? `Finding #${selectedFinding.id}` : ''}
        position="right"
        size={isMobile ? '100%' : 'lg'}
      >
        {selectedFinding && (
          <Stack gap="sm">
            <Group justify="space-between">
              <Group gap="xs">
                <StatusBadge status={selectedFinding.status} />
                <SeverityBadge severity={selectedFinding.severity} />
              </Group>
              <Text size="sm" c="dimmed">{new Date(selectedFinding.detected_at).toLocaleString()}</Text>
            </Group>
            <Text fw={600}>{selectedFinding.service_name || 'unknown service'}</Text>
            <Text size="sm" c="dimmed">
              Host: {findingGroupIndex.get(selectedFinding.id)?.hostLabel || selectedFinding.host_address || 'unknown'}
            </Text>
            <Text>Port: {selectedFinding.port ? `${selectedFinding.port}/${selectedFinding.protocol || 'tcp'}` : '-'}</Text>
            {selectedFinding.description && (
              <Paper p="sm" withBorder>
                <Text size="sm">{selectedFinding.description}</Text>
              </Paper>
            )}
            {parseCves(selectedFinding.cve_ids).length > 0 && (
              <Group gap="xs" wrap="wrap">
                <Text size="sm" c="dimmed">CVEs:</Text>
                {parseCves(selectedFinding.cve_ids).map((cve) => (
                  <Badge
                    key={cve}
                    component="a"
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                    target="_blank"
                    rel="noreferrer"
                    variant="light"
                    color="red"
                    radius="sm"
                  >
                    {cve}
                  </Badge>
                ))}
              </Group>
            )}
            <Group justify="space-between">
              <Text fw={600}>Vulnerability details</Text>
              {!displayedEnrichment && (
                <Button size="xs" variant="light" onClick={async () => {
                  try {
                    await api.post(`/enrichment/finding/${selectedFinding.id}`);
                    notifications.show({ color: 'teal', title: 'Enrichment queued', message: 'Fetching CVSS and references...' });
                    // Poll for enrichment for up to ~20s
                    const started = Date.now();
                    const poll = async () => {
                      try {
                        const res = await api.get(`/finding_ext/${selectedFinding.id}`);
                        const normalized = normalizeEnrichment(res.data?.enrichment);
                        if (normalized) {
                          setSelectedFindingEnrichment(normalized);
                          notifications.show({ color: 'green', title: 'Enrichment complete', message: 'CVSS and references loaded.' });
                          return;
                        }
                      } catch {}
                      if (Date.now() - started < 20000) {
                        setTimeout(poll, 1000);
                      } else {
                        notifications.show({ color: 'yellow', title: 'Still enriching', message: 'Data will appear once available.' });
                      }
                    };
                    setTimeout(poll, 800);
                  } catch (e) {
                    notifications.show({ color: 'red', title: 'Failed to queue enrichment', message: `${e}` });
                  }
                }}>Enrich now</Button>
              )}
            </Group>
            {displayedEnrichment && (
              <Paper p="sm" withBorder>
                <Stack gap={6}>
                  <Group gap="xs">
                    <Text size="sm" c="dimmed">CVSS v3.1:</Text>
                    <Badge color={displayedEnrichment.cvss_v31_base && displayedEnrichment.cvss_v31_base >= 9 ? 'red' : displayedEnrichment.cvss_v31_base && displayedEnrichment.cvss_v31_base >= 7 ? 'orange' : displayedEnrichment.cvss_v31_base && displayedEnrichment.cvss_v31_base >= 4 ? 'yellow' : 'teal'}>
                      {displayedEnrichment.cvss_v31_base ?? '-'}
                    </Badge>
                    {displayedEnrichment.cvss_vector && (
                      <Text size="sm" c="dimmed">{displayedEnrichment.cvss_vector}</Text>
                    )}
                  </Group>
                  {displayedEnrichment.cpe && (
                    <Text size="sm"><Text span c="dimmed">CPE:</Text> {displayedEnrichment.cpe}</Text>
                  )}
                  {displayedEnrichment.references && displayedEnrichment.references.length > 0 && (
                    <Stack gap={4}>
                      <Text size="sm" c="dimmed">References</Text>
                      {displayedEnrichment.references.map((r, idx) => (
                        <Text key={idx} size="sm" component="a" href={r} target="_blank" rel="noreferrer" style={{ overflowWrap: 'anywhere' }}>{r}</Text>
                      ))}
                    </Stack>
                  )}
                </Stack>
              </Paper>
            )}
            {findingGroupIndex.get(selectedFinding.id)?.hostReport && (
              <Paper p="sm" withBorder>
                <Text fw={600} size="sm" mb={4}>Raw nmap output (excerpt)</Text>
                <ScrollArea h={200} offsetScrollbars>
                  <Text component="pre" style={{ whiteSpace: 'pre-wrap', fontFamily: 'SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.85rem' }}>
                    {findingGroupIndex.get(selectedFinding.id)?.hostReport}
                  </Text>
                </ScrollArea>
              </Paper>
            )}
          </Stack>
        )}
      </Drawer>
      <Drawer
        opened={selectedScanId != null}
        onClose={() => setSelectedScanId(null)}
        title={selectedScanId ? `Scan #${selectedScanId} progress` : ''}
        position="right"
        size={isMobile ? '100%' : 'md'}
      >
        {selectedScan && (
          <Group justify="space-between" mb="sm">
            <Group gap="xs">
              <StatusBadge status={selectedScan.status} />
              <Badge variant="light">{selectedScan.profile}</Badge>
            </Group>
            {canWrite && canCancelScan(selectedScan.status) && (
              <Button size="xs" variant="light" color="orange" onClick={() => handleScanCancel(selectedScan.id)}>
                Cancel
              </Button>
            )}
          </Group>
        )}
        <Group justify="space-between" mb="sm">
          <Group gap="xs">
            <Badge variant="light">{scanEvents.length} events</Badge>
            <Badge variant="light" color={eventsAutoRefresh ? 'green' : 'gray'} style={{ cursor: 'pointer' }} onClick={() => setEventsAutoRefresh((v) => !v)}>
              Auto-refresh: {eventsAutoRefresh ? 'ON' : 'OFF'}
            </Badge>
          </Group>
          <Group gap="xs">
            <Button size="xs" variant="light" onClick={() => selectedScanId && api.get(`/scans/${selectedScanId}/events`).then((r) => setScanEvents(r.data))}>Refresh</Button>
            <Button size="xs" variant="light" onClick={() => selectedScanId && api.get(`/scans/${selectedScanId}/assets`).then((r) => setAssetStatuses(r.data))}>Assets</Button>
          </Group>
        </Group>
        <Stack gap={6} mb="sm">
          <Text fw={600} size="sm">Latest events</Text>
          {scanEvents.length === 0 && <Text size="sm" c="dimmed">No events yet.</Text>}
          {scanEvents.slice(0, 3).map((e) => (
            <Group key={`latest-${e.id}`} gap="sm">
              <Text size="xs" c="dimmed" w={160}>
                {new Date(e.created_at).toLocaleString()}
              </Text>
              <Text size="sm">{e.message}</Text>
            </Group>
          ))}
        </Stack>
        {assetStatuses.length > 0 && (
          <Stack gap="xs" mb="sm">
            <Text fw={600} size="sm">Assets in this scan</Text>
            <ScrollArea h={180} offsetScrollbars>
              <Stack gap={6}>
                {assetStatuses.map((row) => (
                  <Group key={row.asset_id} justify="space-between">
                    <Group gap="xs">
                      <Text size="sm">Asset #{row.asset_id}</Text>
                      <StatusBadge status={row.status} />
                    </Group>
                    <Progress
                      className="animate-progress"
                      value={row.status === 'completed' ? 100 : row.status === 'failed' ? 100 : row.status === 'running' ? 66 : 10}
                      w={200}
                      color={row.status === 'failed' ? 'red' : row.status === 'completed' ? 'teal' : 'indigo'}
                      striped={row.status === 'running' || row.status === 'pending'}
                      animated={row.status === 'running' || row.status === 'pending'}
                    />
                  </Group>
                ))}
              </Stack>
            </ScrollArea>
          </Stack>
        )}
        <Text fw={600} size="sm" mb="xs">Event log</Text>
        <ScrollArea h={520} offsetScrollbars>
          <Stack gap={4}>
            {scanEvents.map((e) => (
              <Group key={e.id} gap="sm">
                <Text size="xs" c="dimmed" w={160}>
                  {new Date(e.created_at).toLocaleString()}
                </Text>
                <Text size="sm">{e.message}</Text>
              </Group>
            ))}
          </Stack>
        </ScrollArea>
      </Drawer>
    </AppShell>
  );
}

export default App;
