import React from 'react';
import ReactDOM from 'react-dom/client';
import { MantineProvider, localStorageColorSchemeManager } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import { Global } from '@emotion/react';
import App from './App';
import { theme } from './app/theme';

// Ensure browser tab reflects the product name as early as possible
document.title = 'Clanker Command Console';

// Inject a robot favicon (data URI) to match the Clanker header icon
(function setClankerFavicon() {
  const svg = `<?xml version="1.0" encoding="UTF-8"?><svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' width='256' height='256' fill='none' stroke='%236366f1' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'>
    <rect x='3.5' y='7' width='17' height='12' rx='3' ry='3' fill='transparent'/>
    <path d='M8 7V5a4 4 0 0 1 8 0v2'/>
    <circle cx='9' cy='13' r='1.6' fill='%2322d3ee' stroke='none'/>
    <circle cx='15' cy='13' r='1.6' fill='%23f472b6' stroke='none'/>
    <path d='M12 3v2'/>
    <path d='M7 19h10'/>
    <path d='M6 11h12'/>
  </svg>`;
  const href = `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  const existing = document.querySelector<HTMLLinkElement>("link[rel='icon']#clanker-favicon") || document.createElement('link');
  existing.rel = 'icon';
  existing.id = 'clanker-favicon';
  existing.type = 'image/svg+xml';
  existing.href = href;
  document.head.appendChild(existing);
})();

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <MantineProvider
      defaultColorScheme="dark"
      colorSchemeManager={localStorageColorSchemeManager({ key: 'clanker-color-scheme' })}
      theme={theme}
    >
      <Global
        styles={() => ({
          // One flat background per scheme: no gradients, no glow. Depth comes
          // from borders and a single elevated surface.
          'html[data-mantine-color-scheme="dark"], html[data-mantine-color-scheme="dark"] body': {
            background: '#0B1220',
            color: '#E8EEF7',
          },
          'html[data-mantine-color-scheme="light"], html[data-mantine-color-scheme="light"] body': {
            background: '#F5F7FB',
            color: '#172235',
          },
          body: {
            margin: 0,
            minHeight: '100vh',
            fontFamily: 'Inter, system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
            fontSize: '13.5px',
            WebkitFontSmoothing: 'antialiased',
          },
          '#root': { minHeight: '100vh' },
          // Mantine surface variables, so components inherit the tokens rather
          // than hardcoding hex values in every file.
          'html[data-mantine-color-scheme="dark"]': {
            '--mantine-color-body': '#0B1220',
            '--mantine-color-default-border': '#26344A',
            '--mantine-color-text': '#E8EEF7',
            '--mantine-color-dimmed': '#9AA9BD',
            '--mantine-color-default': '#172235',
            '--mantine-color-default-hover': '#1E293B',
            '--mantine-color-dark-6': '#172235',
            '--mantine-color-dark-7': '#0B1220',
          },
          'html[data-mantine-color-scheme="light"]': {
            '--mantine-color-body': '#F5F7FB',
            '--mantine-color-default-border': '#E1E7EF',
            '--mantine-color-text': '#172235',
            '--mantine-color-dimmed': '#64748B',
            '--mantine-color-gray-0': '#F8FAFC',
          },
          // Technical identifiers stay monospaced and tabular for scanning.
          '.mono, .mantine-Table-td code': {
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
            fontVariantNumeric: 'tabular-nums',
          },
          ':focus-visible': { outline: '2px solid #2563EB', outlineOffset: 2 },
          '@media (prefers-reduced-motion: reduce)': {
            '*, *::before, *::after': { animationDuration: '0.001ms !important', transitionDuration: '0.001ms !important' },
          },
        })}
      />
      {/* Keep Mantine's own animated stripes by not overriding its animation property */}
      <Notifications position="top-right" zIndex={1000} />
      <App />
    </MantineProvider>
  </React.StrictMode>,
);
