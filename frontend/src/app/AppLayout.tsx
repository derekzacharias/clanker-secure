import { useMemo, useState } from 'react';
import {
  ActionIcon,
  AppShell,
  Box,
  Burger,
  Divider,
  Drawer,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Stack,
  Text,
  ThemeIcon,
  Tooltip,
  UnstyledButton,
  useMantineColorScheme,
} from '@mantine/core';
import {
  IconBinaryTree2,
  IconBug,
  IconCalendarStats,
  IconChevronDown,
  IconLayoutDashboard,
  IconLayoutSidebarLeftCollapse,
  IconLayoutSidebarLeftExpand,
  IconListSearch,
  IconLogout,
  IconMoon,
  IconPlugConnected,
  IconServer2,
  IconSettings,
  IconShieldCheck,
  IconSun,
  IconUserCircle,
  IconUsers,
} from '@tabler/icons-react';
import { Link } from './Link';
import { ROUTE_META, ROUTES, isActive, usePathname, type RouteName } from './router';
import { tokens } from './theme';

export interface SessionUser {
  id?: number;
  email: string;
  name?: string | null;
  role: string;
}

interface NavItem {
  route: RouteName;
  label: string;
  icon: React.ReactNode;
  /** Hidden when the session cannot use it. */
  requiresWrite?: boolean;
  adminOnly?: boolean;
}

const PRIMARY: NavItem[] = [
  { route: 'overview', label: 'Overview', icon: <IconLayoutDashboard size={18} /> },
  { route: 'assets', label: 'Assets', icon: <IconServer2 size={18} /> },
  { route: 'scans', label: 'Scans', icon: <IconShieldCheck size={18} /> },
  { route: 'findings', label: 'Findings', icon: <IconBug size={18} /> },
  { route: 'reports', label: 'Reports', icon: <IconBinaryTree2 size={18} /> },
];

const SECONDARY: NavItem[] = [
  { route: 'schedules', label: 'Schedules', icon: <IconCalendarStats size={18} /> },
  { route: 'coverage', label: 'Rule coverage', icon: <IconListSearch size={18} />, requiresWrite: true },
  { route: 'integrations', label: 'Integrations', icon: <IconPlugConnected size={18} /> },
  { route: 'settings', label: 'Settings', icon: <IconSettings size={18} /> },
  { route: 'administration', label: 'Administration', icon: <IconUsers size={18} />, adminOnly: true },
];

const ROLE_LABEL: Record<string, string> = {
  admin: 'Administrator',
  operator: 'Operator',
  viewer: 'Viewer',
};

function visible(items: NavItem[], role: string | undefined, canWrite: boolean) {
  return items.filter((item) => {
    if (item.adminOnly && role !== 'admin') return false;
    if (item.requiresWrite && !canWrite) return false;
    return true;
  });
}

const COLLAPSE_KEY = 'clanker-nav-collapsed';

export function AppLayout({
  user,
  canWrite,
  onLogout,
  onOpenProfile,
  onOpenPassword,
  actions,
  children,
}: {
  user: SessionUser | null;
  canWrite: boolean;
  onLogout: () => void;
  onOpenProfile: () => void;
  onOpenPassword: () => void;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const route = (ROUTES.find((r) => isActive(r, pathname)) ?? 'overview') as RouteName;
  const meta = ROUTE_META[route];
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSE_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [drawerOpen, setDrawerOpen] = useState(false);

  const primaryItems = useMemo(() => visible(PRIMARY, user?.role, canWrite), [user?.role, canWrite]);
  const secondaryItems = useMemo(() => visible(SECONDARY, user?.role, canWrite), [user?.role, canWrite]);

  function toggleCollapsed() {
    setCollapsed((value) => {
      const next = !value;
      try {
        localStorage.setItem(COLLAPSE_KEY, next ? '1' : '0');
      } catch {
        /* storage unavailable: collapse state stays in memory */
      }
      return next;
    });
  }

  const renderNav = (compact: boolean, onNavigate?: () => void) => {
    const item = (entry: NavItem) => {
      const active = isActive(entry.route, pathname);
      const link = (
        <NavLink
          key={entry.route}
          component={Link}
          to={`/${entry.route}`}
          active={active}
          aria-current={active ? 'page' : undefined}
          onClick={onNavigate}
          label={compact ? undefined : entry.label}
          leftSection={
            <ThemeIcon variant={active ? 'light' : 'transparent'} color={active ? 'brand' : 'gray'} size={28} radius="md">
              {entry.icon}
            </ThemeIcon>
          }
          styles={{
            root: { borderRadius: tokens.radius.md, minHeight: 38 },
            label: { fontSize: 13.5, fontWeight: active ? 600 : 450 },
          }}
        />
      );
      return compact ? (
        <Tooltip key={entry.route} label={entry.label} position="right">
          <div>{link}</div>
        </Tooltip>
      ) : (
        link
      );
    };
    return (
      <Stack gap={2}>
        {primaryItems.map(item)}
        <Divider my="xs" label={compact ? undefined : 'Operations'} labelPosition="left" />
        {secondaryItems.map(item)}
      </Stack>
    );
  };

  const brand = (
    <Group gap="xs" wrap="nowrap" px={collapsed ? 0 : 4} justify={collapsed ? 'center' : 'flex-start'}>
      <ThemeIcon size={30} radius="md" variant="light" color="brand" aria-hidden>
        <IconShieldCheck size={18} />
      </ThemeIcon>
      {!collapsed && (
        <Box>
          <Text fw={700} size="sm" lh={1.1}>
            Clanker Guard
          </Text>
          <Text size="xs" c="dimmed" lh={1.2}>
            Security console
          </Text>
        </Box>
      )}
    </Group>
  );

  const accountMenu = (
    <Menu position="bottom-end" withArrow width={230} shadow="md">
      <Menu.Target>
        <UnstyledButton
          aria-label="Account menu"
          style={{ width: '100%', borderRadius: tokens.radius.md }}
          px={8}
          py={6}
        >
          <Group gap="xs" wrap="nowrap" justify={collapsed ? 'center' : 'space-between'}>
            <Group gap="xs" wrap="nowrap">
              <ThemeIcon variant="light" color="gray" size={28} radius="xl" aria-hidden>
                <IconUserCircle size={18} />
              </ThemeIcon>
              {!collapsed && (
                <Box style={{ minWidth: 0 }}>
                  <Text size="sm" fw={600} truncate>
                    {user?.name || user?.email || 'Signed in'}
                  </Text>
                  <Text size="xs" c="dimmed" truncate>
                    {ROLE_LABEL[user?.role ?? ''] ?? user?.role ?? 'unknown role'}
                  </Text>
                </Box>
              )}
            </Group>
            {!collapsed && <IconChevronDown size={14} aria-hidden />}
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>{user?.email ?? 'Account'}</Menu.Label>
        <Menu.Item leftSection={<IconUserCircle size={16} />} onClick={onOpenProfile}>
          Profile
        </Menu.Item>
        <Menu.Item leftSection={<IconSettings size={16} />} onClick={onOpenPassword}>
          Change password
        </Menu.Item>
        <Menu.Divider />
        <Menu.Label>Appearance</Menu.Label>
        <Menu.Item
          leftSection={colorScheme === 'dark' ? <IconSun size={16} /> : <IconMoon size={16} />}
          onClick={() => setColorScheme(colorScheme === 'dark' ? 'light' : 'dark')}
        >
          Use {colorScheme === 'dark' ? 'light' : 'dark'} theme
        </Menu.Item>
        <Menu.Divider />
        <Menu.Item color="red" leftSection={<IconLogout size={16} />} onClick={onLogout}>
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );

  return (
    <AppShell
      header={{ height: tokens.headerHeight }}
      navbar={{
        width: collapsed ? tokens.sidebarCollapsedWidth : tokens.sidebarWidth,
        breakpoint: 'md',
        collapsed: { mobile: true },
      }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" gap="sm" justify="space-between" wrap="nowrap">
          <Group gap="xs" wrap="nowrap">
            <Burger opened={drawerOpen} onClick={() => setDrawerOpen(true)} hiddenFrom="md" size="sm" aria-label="Open navigation" />
            <Box visibleFrom="md">
              <Group gap={4} wrap="nowrap">
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  onClick={toggleCollapsed}
                  aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
                  title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
                >
                  {collapsed ? <IconLayoutSidebarLeftExpand size={18} /> : <IconLayoutSidebarLeftCollapse size={18} />}
                </ActionIcon>
              </Group>
            </Box>
            <Box>
              <Text component="h1" fw={650} size="md" lh={1.2}>
                {meta.title}
              </Text>
              <Text size="xs" c="dimmed" lh={1.2} visibleFrom="sm">
                {meta.description}
              </Text>
            </Box>
          </Group>
          <Group gap="xs" wrap="nowrap">
            {actions}
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p={collapsed ? 6 : 'sm'} aria-label="Primary">
        <AppShell.Section>{brand}</AppShell.Section>
        <AppShell.Section grow component={ScrollArea} mt="sm">
          {renderNav(collapsed)}
        </AppShell.Section>
        <AppShell.Section>
          <Divider mb="xs" />
          {accountMenu}
        </AppShell.Section>
      </AppShell.Navbar>

      <Drawer
        opened={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="Navigation"
        size={tokens.sidebarWidth + 24}
        hiddenFrom="md"
        padding="sm"
      >
        <Stack gap="md">
          {brand}
          {renderNav(false, () => setDrawerOpen(false))}
          <Divider />
          <Stack gap={4}>
            <Text size="xs" c="dimmed">
              {user?.email} · {ROLE_LABEL[user?.role ?? ''] ?? user?.role}
            </Text>
            <NavLink
              label="Profile"
              leftSection={<ThemeIcon variant="transparent" size={26}><IconUserCircle size={16} /></ThemeIcon>}
              onClick={() => {
                setDrawerOpen(false);
                onOpenProfile();
              }}
            />
            <NavLink
              label={colorScheme === 'dark' ? 'Use light theme' : 'Use dark theme'}
              leftSection={<ThemeIcon variant="transparent" size={26}>{colorScheme === 'dark' ? <IconSun size={16} /> : <IconMoon size={16} />}</ThemeIcon>}
              onClick={() => setColorScheme(colorScheme === 'dark' ? 'light' : 'dark')}
            />
            <NavLink
              label="Sign out"
              leftSection={<ThemeIcon variant="transparent" size={26}><IconLogout size={16} /></ThemeIcon>}
              onClick={() => {
                setDrawerOpen(false);
                onLogout();
              }}
            />
          </Stack>
        </Stack>
      </Drawer>

      <AppShell.Main>{children}</AppShell.Main>
    </AppShell>
  );
}
