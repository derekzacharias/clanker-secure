import { useEffect, useMemo, useState } from 'react';
import {
  AppShell,
  Badge,
  Button,
  Card,
  Grid,
  Group,
  MultiSelect,
  Paper,
  Progress,
  RingProgress,
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
  Drawer,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
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
} from '@tabler/icons-react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

interface Asset {
  id: number;
  name?: string | null;
  target: string;
  environment?: string | null;
  owner?: string | null;
  notes?: string | null;
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
  severity: string;
  status: string;
  description?: string | null;
  detected_at: string;
  cve_ids?: string | null;
  cvss_v31_base?: number | null;
  cvss_vector?: string | null;
  references?: string[] | null;
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
  running: 'blue',
  completed: 'teal',
  completed_with_errors: 'orange',
  failed: 'red',
};

const SEVERITY_COLORS: Record<string, string> = {
  informational: 'gray',
  low: 'green',
  medium: 'yellow',
  high: 'red',
  critical: 'pink',
};

const api = axios.create({ baseURL: API_BASE, timeout: 15000 });

const parseCves = (raw?: string | null): string[] => {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.filter((item) => typeof item === 'string');
    }
  } catch {
    // ignore parse errors
  }
  if (typeof raw === 'string' && raw.toUpperCase().includes('CVE-')) {
    return raw.split(/[,;\\s]+/).filter((token) => token.toUpperCase().startsWith('CVE-'));
  }
  return [];
};

const exportCsv = (rows: Record<string, any>[], filename: string) => {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const csvLines = [headers.join(',')].concat(
    rows.map((row) =>
      headers
        .map((h) => {
          const value = row[h] ?? '';
          const escaped = String(value).replace(/\"/g, '\"\"');
          return `"${escaped}"`;
        })
        .join(','),
    ),
  );
  const blob = new Blob([csvLines.join('\\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const exportJson = (data: unknown, filename: string) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const glassStyles = {
  background: 'rgba(13, 21, 37, 0.72)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  backdropFilter: 'blur(18px)',
};

const hostCardStyles = {
  background: 'linear-gradient(135deg, rgba(15,23,42,0.92), rgba(30,41,59,0.85))',
  border: '1px solid rgba(59,130,246,0.25)',
  boxShadow: '0 25px 40px rgba(15,23,42,0.6)',
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
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [findingFilter, setFindingFilter] = useState<'all' | 'low' | 'medium' | 'high' | 'critical'>('all');
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [scanEvents, setScanEvents] = useState<{ id: number; created_at: string; message: string }[]>([]);
  const [eventsAutoRefresh, setEventsAutoRefresh] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const [assetForm, setAssetForm] = useState({ name: '', target: '', environment: '', owner: '', notes: '' });
  const [editingAssetId, setEditingAssetId] = useState<number | null>(null);
  const [scanForm, setScanForm] = useState({ profile: 'intense' });
  const [selectedAssetIds, setSelectedAssetIds] = useState<string[]>([]);

  const refreshAll = async () => {
    setLoading(true);
    try {
      const [assetRes, scanRes, findingRes] = await Promise.all([
        api.get<Asset[]>('/assets'),
        api.get<Scan[]>('/scans'),
        api.get<Finding[]>('/findings'),
      ]);
      setAssets(assetRes.data);
      setScans(scanRes.data);
      setFindings(findingRes.data);
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
    if (!autoRefresh) return undefined;
    const interval = setInterval(refreshAll, 120000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  useEffect(() => {
    if (selectedScanId == null) {
      setScanEvents([]);
      return;
    }
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.get(`/scans/${selectedScanId}/events`);
        if (!cancelled) {
          setScanEvents(res.data);
        }
      } catch (error) {
        if (!cancelled) {
          notifications.show({ color: 'red', title: 'Failed to load scan events', message: String(error) });
        }
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [selectedScanId]);

  useEffect(() => {
    if (selectedScanId == null || !eventsAutoRefresh) return () => {};
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
          } catch {
            // ignore malformed payloads
          }
        };
        es.onerror = () => {
          if (es) {
            es.close();
            es = null;
            setTimeout(() => open(), 1500);
          }
        };
      } catch {
        // ignore EventSource errors
      }
    };
    open();
    return () => {
      if (es) es.close();
    };
  }, [selectedScanId, eventsAutoRefresh]);

  const resetAssetForm = () => {
    setAssetForm({ name: '', target: '', environment: '', owner: '', notes: '' });
    setEditingAssetId(null);
  };

  const handleAssetSubmit = async () => {
    try {
      const payload = {
        name: assetForm.name || null,
        target: assetForm.target,
        environment: assetForm.environment || null,
        owner: assetForm.owner || null,
        notes: assetForm.notes || null,
      };
      if (editingAssetId != null) {
        await api.patch('/assets/' + editingAssetId, payload);
        notifications.show({ color: 'green', title: 'Asset updated', message: assetForm.target });
      } else {
        await api.post('/assets', payload);
        notifications.show({ color: 'green', title: 'Asset added', message: assetForm.target });
      }
      resetAssetForm();
      refreshAll();
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to save asset', message: String(error) });
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
    });
  };

  const handleScanSubmit = async () => {
    const assetIds = selectedAssetIds.map((value) => parseInt(value, 10)).filter((value) => !Number.isNaN(value));
    if (assetIds.length === 0) {
      notifications.show({ color: 'yellow', title: 'Provide asset IDs', message: 'Add at least one asset ID' });
      return;
    }
    try {
      await api.post('/scans', { asset_ids: assetIds, profile: scanForm.profile });
      notifications.show({ color: 'green', title: 'Scan queued', message: `${assetIds.length} asset(s)` });
      setSelectedAssetIds([]);
      refreshAll();
    } catch (error) {
      notifications.show({ color: 'red', title: 'Failed to queue scan', message: `${error}` });
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

  const severityRingData = Object.entries(severitySummary).map(([severity, count]) => ({
    value: count,
    color: SEVERITY_COLORS[severity] || 'gray',
    tooltip: `${severity.toUpperCase()}: ${count}`,
  }));

  const assetLookup = useMemo(() => {
    const map = new Map<number, Asset>();
    assets.forEach((asset) => map.set(asset.id, asset));
    return map;
  }, [assets]);

  const filteredFindings = useMemo(() => {
    if (findingFilter === 'all') return findings;
    return findings.filter((finding) => finding.severity.toLowerCase() === findingFilter);
  }, [findings, findingFilter]);

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
      group.findings.forEach((finding) => {
        map.set(finding.id, { hostLabel: group.hostLabel, hostReport: group.hostReport });
      });
    });
    return map;
  }, [findingsByHost]);

  return (
    <AppShell padding="lg" header={{ height: 70 }} styles={{ main: { background: 'transparent' } }}>
      <AppShell.Header style={{ background: 'rgba(5,8,15,0.7)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <Group justify="space-between" px="lg" py="sm">
          <Group gap="md" align="center" wrap="nowrap">
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
                  background: 'linear-gradient(120deg, #22d3ee, #a3e635)',
                  WebkitBackgroundClip: 'text',
                  color: 'transparent',
                  margin: 0,
                }}
              >
                Clanker Command Console
              </Text>
              <Text size="sm" c="dimmed">
                Network awareness & vulnerability visibility
              </Text>
            </div>
          </Group>
          <Group gap="sm">
            <Badge color={activeScans > 0 ? 'blue' : 'gray'} variant="filled">
              Active scans: {activeScans}
            </Badge>
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
            <Button variant="subtle" component="a" href="/legacy" target="_blank" leftSection={<IconShieldCheck size={14} />}>
              Legacy UI
            </Button>
            <Tooltip label="Refresh data now">
              <Button leftSection={<IconRefresh size={16} />} variant="gradient" gradient={{ from: 'cyan', to: 'lime' }} onClick={refreshAll} loading={loading}>
                Refresh
              </Button>
            </Tooltip>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Main>
        <Stack gap="xl">
          <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
            {[
              {
                label: 'Assets',
                value: assets.length,
                icon: IconTarget,
                subtitle: 'Managed hosts',
                gradient: 'linear-gradient(135deg, rgba(129,230,217,0.35), rgba(79,70,229,0.25))',
                iconGradient: { from: 'cyan', to: 'indigo' },
              },
              {
                label: 'Active scans',
                value: activeScans,
                icon: IconRadar2,
                subtitle: 'Queued / running',
                gradient: 'linear-gradient(135deg, rgba(59,130,246,0.35), rgba(14,165,233,0.25))',
                iconGradient: { from: 'blue', to: 'teal' },
              },
              {
                label: 'Open findings',
                value: openFindings,
                icon: IconAlertTriangle,
                subtitle: 'Remediation backlog',
                gradient: 'linear-gradient(135deg, rgba(252,165,165,0.35), rgba(234,88,12,0.3))',
                iconGradient: { from: 'orange', to: 'red' },
              },
              {
                label: 'Total findings',
                value: findings.length,
                icon: IconSparkles,
                subtitle: 'Captured issues',
                gradient: 'linear-gradient(135deg, rgba(248,250,252,0.2), rgba(148,163,184,0.2))',
                iconGradient: { from: 'grape', to: 'pink' },
              },
            ].map((card) => (
              <Card key={card.label} padding="lg" style={gradientCard(card.gradient)} radius="md" shadow="xl">
                <Group justify="space-between" mb="xs">
                  <Text c="gray.2" size="sm">
                    {card.label}
                  </Text>
                  <ThemeIcon variant="gradient" gradient={card.iconGradient} radius="xl" size="lg">
                    <card.icon size={18} />
                  </ThemeIcon>
                </Group>
                <Title order={2}>{card.value}</Title>
                <Text size="sm" c="gray.4">
                  {card.subtitle}
                </Text>
              </Card>
            ))}
          </SimpleGrid>

          <Grid>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                <Group justify="space-between" mb="md">
                  <div>
                    <Title order={5}>Scan status</Title>
                    <Text size="sm" c="dimmed">
                      Lifecycle snapshot
                    </Text>
                  </div>
                  <ThemeIcon variant="light" color="blue">
                    <IconShieldCheck size={18} />
                  </ThemeIcon>
                </Group>
                <Stack gap="xs">
                  {Object.keys(scanStatusSummary).length === 0 && <Text c="dimmed">No scans yet.</Text>}
                  {Object.entries(scanStatusSummary).map(([status, count]) => (
                    <Paper key={status} withBorder p="sm" radius="md" style={{ background: 'rgba(15,23,42,0.5)' }}>
                      <Group justify="space-between">
                        <Group gap="sm">
                          <StatusBadge status={status} />
                          <Text size="sm" c="gray.5">
                            {status.replaceAll('_', ' ')}
                          </Text>
                        </Group>
                        <Group gap="xs">
                          <Text fw={600}>{count}</Text>
                          <Progress value={Math.min(100, (count / Math.max(scans.length, 1)) * 100)} w={120} color={STATUS_COLORS[status] || 'gray'} />
                        </Group>
                      </Group>
                    </Paper>
                  ))}
                </Stack>
              </Card>
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                <Group justify="space-between" mb="md">
                  <div>
                    <Title order={5}>Findings by severity</Title>
                    <Text size="sm" c="dimmed">
                      Distribution of latest scan results
                    </Text>
                  </div>
                </Group>
                <Group wrap="nowrap" gap="lg">
                  <RingProgress
                    size={160}
                    thickness={16}
                    sections={severityRingData.length ? severityRingData : [{ value: 100, color: '#334155' }]}
                    label={
                      <Stack gap={0} align="center">
                        <Text size="sm" c="gray.5">
                          Severity
                        </Text>
                        <Title order={4}>{findings.length}</Title>
                      </Stack>
                    }
                  />
                  <Stack gap="xs">
                    {Object.entries(severitySummary)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([severity, count]) => (
                        <Group key={severity} justify="space-between" w={220}>
                          <SeverityBadge severity={severity} />
                          <Text fw={600}>{count}</Text>
                        </Group>
                      ))}
                  </Stack>
                </Group>
              </Card>
            </Grid.Col>
          </Grid>

          <Tabs defaultValue="assets" radius="md" variant="pills">
            <Tabs.List style={{ background: 'rgba(15,23,42,0.6)', borderRadius: 999, padding: 4 }}>
              <Tabs.Tab value="assets">Assets</Tabs.Tab>
              <Tabs.Tab value="scans">Scans</Tabs.Tab>
              <Tabs.Tab value="findings">Findings</Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel value="assets" pt="md">
              <Grid>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                    <Group justify="space-between" mb="sm">
                      <Title order={5}>{editingAssetId != null ? ('Edit asset #' + editingAssetId) : 'Add asset'}</Title>
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
                      <Button leftSection={<IconSend size={16} />} onClick={handleAssetSubmit} disabled={!assetForm.target.trim()}>
                        Save asset
                      </Button>
                    </Stack>
                  </Card>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 8 }}>
                  <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                    <Group justify="space-between" mb="sm">
                      <Title order={5}>Assets</Title>
                      <Button size="xs" variant="light" onClick={resetAssetForm}>
                        Add
                      </Button>
                    </Group>
                    <ScrollArea h={360} offsetScrollbars>
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
                          {assets.map((asset) => (
                            <Table.Tr key={asset.id}>
                              <Table.Td>{asset.id}</Table.Td>
                              <Table.Td>{asset.target}</Table.Td>
                              <Table.Td>{asset.name || '-'}</Table.Td>
                              <Table.Td>{asset.environment || '-'}</Table.Td>
                              <Table.Td>{asset.owner || '-'}</Table.Td>
                              <Table.Td>
                                <Button size="xs" color="red" variant="light" onClick={() => handleAssetDelete(asset.id)}>
                                  Remove
                                </Button>
                              </Table.Td>
                            </Table.Tr>
                          ))}
                        </Table.Tbody>
                      </Table>
                    </ScrollArea>
                  </Card>
                </Grid.Col>
              </Grid>
            </Tabs.Panel>

            <Tabs.Panel value="scans" pt="md">
              <Grid>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                    <Group justify="space-between" mb="sm">
                      <Title order={5}>{editingAssetId != null ? ('Edit asset #' + editingAssetId) : 'Add asset'}</Title>
                      {editingAssetId != null && (
                        <Button size="xs" variant="light" color="gray" onClick={resetAssetForm}>
                          Cancel
                        </Button>
                      )}
                    </Group>
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
                      <Button onClick={handleScanSubmit}>Start scan</Button>
                    </Stack>
                  </Card>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 8 }}>
                  <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                    <Group justify="space-between" mb="sm">
                      <Title order={5}>Assets</Title>
                      <Button size="xs" variant="light" onClick={resetAssetForm}>
                        Add
                      </Button>
                    </Group>
                    <ScrollArea h={360} offsetScrollbars>
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
                          {scans.map((scan) => (
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
                  </Card>
                </Grid.Col>
              </Grid>
            </Tabs.Panel>

            <Tabs.Panel value="findings" pt="md">
              <Card padding="lg" radius="md" style={glassStyles} shadow="xl">
                <Group justify="space-between" mb="md">
                  <Title order={5}>Findings</Title>
                  <Group gap="xs">
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
                    <Button
                      variant="light"
                      onClick={() =>
                        exportCsv(
                          filteredFindings.map((f) => ({
                            id: f.id,
                            asset_id: f.asset_id,
                            scan_id: f.scan_id,
                            host: f.host_address,
                            port: f.port,
                            protocol: f.protocol,
                            service: f.service_name,
                            severity: f.severity,
                            status: f.status,
                            detected_at: f.detected_at,
                            cve_ids: parseCves(f.cve_ids).join(';'),
                            cvss_v31_base: f.cvss_v31_base ?? '',
                            cvss_vector: f.cvss_vector ?? '',
                            references: (f.references ?? []).join(';'),
                          })),
                          'findings.csv',
                        )
                      }
                    >
                      Export CSV
                    </Button>
                    <Button variant="light" onClick={() => exportJson(filteredFindings, 'findings.json')}>
                      Export JSON
                    </Button>
                  </Group>
                </Group>
                <Stack gap="md">
                  {findingsByHost.length === 0 && <Text c="dimmed">No findings to summarize.</Text>}
                  {findingsByHost.map((group) => (
                    <Paper key={group.hostLabel} withBorder p="md" radius="md" style={hostCardStyles}>
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
                            <Table.Th>CVEs</Table.Th>
                            <Table.Th>CVSS</Table.Th>
                            <Table.Th>SEVERITY</Table.Th>
                            <Table.Th>STATUS</Table.Th>
                            <Table.Th>DETECTED</Table.Th>
                          </Table.Tr>
                        </Table.Thead>
                        <Table.Tbody>
                          {group.findings
                            .sort((a, b) => (a.port ?? 0) - (b.port ?? 0))
                            .map((finding) => (
                              <Table.Tr key={`${group.hostLabel}-${finding.id}`} onClick={() => setSelectedFinding(finding)} style={{ cursor: 'pointer' }}>
                                <Table.Td>{finding.port ? `${finding.port}/${finding.protocol || 'tcp'}` : '-'}</Table.Td>
                                <Table.Td>{finding.service_name || 'unknown'}</Table.Td>
                                <Table.Td>
                                  <Group gap={4} wrap="wrap">
                                    {parseCves(finding.cve_ids).map((cve) => (
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
                                    {parseCves(finding.cve_ids).length === 0 && <Text size="xs" c="dimmed">-</Text>}
                                  </Group>
                                </Table.Td>
                                <Table.Td>
                                  <Badge
                                    variant="outline"
                                    color={
                                      finding.cvss_v31_base != null
                                        ? finding.cvss_v31_base >= 9
                                          ? 'red'
                                          : finding.cvss_v31_base >= 7
                                            ? 'orange'
                                            : finding.cvss_v31_base >= 4
                                              ? 'yellow'
                                              : 'teal'
                                        : 'gray'
                                    }
                                  >
                                    {finding.cvss_v31_base ?? '—'}
                                  </Badge>
                                </Table.Td>
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
                            <Text fw={600} size="sm">
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
              </Card>
            </Tabs.Panel>
          </Tabs>
        </Stack>
        <Drawer
          opened={selectedFinding != null}
          onClose={() => setSelectedFinding(null)}
          title={selectedFinding ? `Finding #${selectedFinding.id}` : ''}
          position="right"
          size="lg"
        >
          {selectedFinding && (
            <Stack gap="sm">
              <Group justify="space-between">
                <Group gap="xs">
                  <StatusBadge status={selectedFinding.status} />
                  <SeverityBadge severity={selectedFinding.severity} />
                </Group>
                <Text size="sm" c="dimmed">
                  {new Date(selectedFinding.detected_at).toLocaleString()}
                </Text>
              </Group>
              <Text fw={600}>{selectedFinding.service_name || 'unknown service'}</Text>
              <Text size="sm" c="dimmed">
                Host: {findingGroupIndex.get(selectedFinding.id)?.hostLabel || selectedFinding.host_address || 'unknown'}
              </Text>
              <Text size="sm">Port: {selectedFinding.port ? `${selectedFinding.port}/${selectedFinding.protocol || 'tcp'}` : '-'}</Text>
              {parseCves(selectedFinding.cve_ids).length > 0 && (
                <Group gap="xs" wrap="wrap">
                  <Text size="sm" c="dimmed">
                    CVEs:
                  </Text>
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
              <Group gap="xs">
                <Text size="sm" c="dimmed">
                  CVSS v3.1:
                </Text>
                <Badge
                  color={
                    selectedFinding.cvss_v31_base != null
                      ? selectedFinding.cvss_v31_base >= 9
                        ? 'red'
                        : selectedFinding.cvss_v31_base >= 7
                          ? 'orange'
                          : selectedFinding.cvss_v31_base >= 4
                            ? 'yellow'
                            : 'teal'
                      : 'gray'
                  }
                  variant="light"
                >
                  {selectedFinding.cvss_v31_base ?? 'Not enriched'}
                </Badge>
                {selectedFinding.cvss_vector && (
                  <Text size="sm" c="dimmed">
                    {selectedFinding.cvss_vector}
                  </Text>
                )}
              </Group>
              {selectedFinding.references && selectedFinding.references.length > 0 && (
                <Stack gap={4}>
                  <Text size="sm" c="dimmed">
                    References
                  </Text>
                  {selectedFinding.references.map((ref, idx) => (
                    <Text key={idx} size="sm" component="a" href={ref} target="_blank" rel="noreferrer" style={{ overflowWrap: 'anywhere' }}>
                      {ref}
                    </Text>
                  ))}
                </Stack>
              )}
              {findingGroupIndex.get(selectedFinding.id)?.hostReport && (
                <Paper p="sm" withBorder>
                  <Text fw={600} size="sm" mb={4}>
                    Raw nmap output (excerpt)
                  </Text>
                  <ScrollArea h={200} offsetScrollbars>
                    <Text
                      component="pre"
                      style={{ whiteSpace: 'pre-wrap', fontFamily: 'SFMono-Regular, Menlo, Monaco, Consolas, monospace', fontSize: '0.85rem' }}
                    >
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
          size="md"
        >
          <Group justify="space-between" mb="sm">
            <Badge variant="light">{scanEvents.length} events</Badge>
            <Group gap="xs">
              <Badge
                variant="light"
                color={eventsAutoRefresh ? 'green' : 'gray'}
                style={{ cursor: 'pointer' }}
                onClick={() => setEventsAutoRefresh((v) => !v)}
              >
                Auto-refresh: {eventsAutoRefresh ? 'ON' : 'OFF'}
              </Badge>
              <Button
                size="xs"
                variant="light"
                onClick={() => selectedScanId && api.get(`/scans/${selectedScanId}/events`).then((r) => setScanEvents(r.data))}
              >
                Refresh
              </Button>
            </Group>
          </Group>
          <Stack gap={6} mb="sm">
            <Text fw={600} size="sm">
              Latest events
            </Text>
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
          <Text fw={600} size="sm" mb="xs">
            Event log
          </Text>
          <ScrollArea h={420} offsetScrollbars>
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
      </AppShell.Main>
    </AppShell>
  );
}

export default App;
