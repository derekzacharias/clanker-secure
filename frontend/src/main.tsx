import React from 'react';
import ReactDOM from 'react-dom/client';
import { MantineProvider, localStorageColorSchemeManager } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import { Global } from '@emotion/react';
import App from './App';

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
      theme={{
        primaryColor: 'indigo',
        fontFamily: 'Inter, system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
        headings: { fontFamily: 'Space Grotesk, Inter, sans-serif' },
      }}
    >
      <Global
        styles={{
          body: {
            margin: 0,
            minHeight: '100vh',
            background:
              'radial-gradient(1200px 600px at 10% -10%, rgba(99,102,241,0.18), transparent 60%), radial-gradient(900px 500px at 110% 0%, rgba(56,189,248,0.16), transparent 55%), radial-gradient(700px 400px at 50% 120%, rgba(147,51,234,0.12), transparent 60%), #0a0f1c',
            color: '#f8fafc',
            fontFamily: 'Inter, sans-serif',
          },
          'html[data-mantine-color-scheme="light"] body': {
            background:
              'radial-gradient(1400px 700px at 0% -20%, rgba(99,102,241,0.24), transparent 60%), radial-gradient(1200px 600px at 100% -10%, rgba(14,165,233,0.22), transparent 55%), radial-gradient(900px 500px at 50% 120%, rgba(167,139,250,0.20), transparent 60%), #e8eefc',
            color: '#0b1220',
          },
          '#root': {
            minHeight: '100vh',
          },
          // Smooth progress bar updates
          '.animate-progress .mantine-Progress-section': {
            transition: 'width 700ms ease',
            willChange: 'width',
          },
        }}
      />
      {/* Keep Mantine's own animated stripes by not overriding its animation property */}
      <Notifications position="top-right" zIndex={1000} />
      <App />
    </MantineProvider>
  </React.StrictMode>,
);
