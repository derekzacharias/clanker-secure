import { Box, Group, Text, UnstyledButton } from '@mantine/core';
import { IconCheck, IconCopy } from '@tabler/icons-react';
import { useId, useRef, useState } from 'react';
import { surfaceTokens } from '../../app/theme';

/**
 * Gray technical output block.
 *
 * Commands, raw scanner output, JSON and logs must be immediately recognisable as
 * not-prose. One component keeps them consistent: monospace, the code surface from
 * the theme (never the panel colour), a border, optional language label and a copy
 * button that reports its own state.
 *
 * Content is always rendered as text inside `pre`/`code` — never as HTML — because
 * scan output, agent banners and ticket bodies are untrusted input.
 */
export function CodeBlock({
  children,
  language,
  copyable = true,
  wrap = false,
  maxHeight,
  scheme,
}: {
  children: string;
  /** Label shown in the header: Bash, PowerShell, JSON, Nmap output, Log … */
  language?: string;
  copyable?: boolean;
  /** Wrap long lines (logs, scanner output) instead of scrolling horizontally. */
  wrap?: boolean;
  maxHeight?: number | string;
  /** Colour scheme in use; Mantine's useMantineColorScheme value. */
  scheme?: 'light' | 'dark';
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'manual'>('idle');
  const id = useId();
  const preRef = useRef<HTMLPreElement>(null);
  const resolved = scheme ?? (typeof document !== 'undefined' && document.documentElement.dataset.mantineColorScheme === 'light' ? 'light' : 'dark');
  const tokens = surfaceTokens(resolved);

  async function copy() {
    try {
      await navigator.clipboard.writeText(children);
      setState('copied');
      window.setTimeout(() => setState('idle'), 1500);
    } catch {
      // Clipboard unavailable (insecure context or permission): select the text so
      // the operator can copy it manually instead of getting a silent no-op.
      const selection = window.getSelection();
      if (selection && preRef.current) {
        const range = document.createRange();
        range.selectNodeContents(preRef.current);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      // Say what happened rather than nothing: the text is selected and Ctrl+C works.
      setState('manual');
    }
  }

  const showHeader = Boolean(language) || copyable;

  return (
    <Box
      style={{
        border: `1px solid ${tokens.codeBorder}`,
        borderRadius: 8,
        overflow: 'hidden',
        background: tokens.codeBg,
      }}
    >
      {showHeader ? (
        <Group
          justify="space-between"
          wrap="nowrap"
          px={14}
          py={6}
          style={{
            background: tokens.sectionHeader,
            borderBottom: `1px solid ${tokens.codeBorder}`,
          }}
        >
          <Text size="xs" fw={600} style={{ color: tokens.codeMuted, letterSpacing: 0.3 }}>
            {language ?? 'Code'}
          </Text>
          {copyable ? (
            <UnstyledButton
              onClick={copy}
              aria-label={state === 'copied' ? 'Copied' : state === 'manual' ? 'Press Ctrl+C to copy the selected text' : 'Copy to clipboard'}
              style={{ color: state === 'idle' ? tokens.codeMuted : tokens.codeText, display: 'flex', alignItems: 'center', gap: 4 }}
            >
              {state === 'copied' ? <IconCheck size={14} /> : <IconCopy size={14} />}
              <Text size="xs" style={{ color: 'inherit' }}>
                {state === 'copied' ? 'Copied' : state === 'manual' ? 'Ctrl+C' : 'Copy'}
              </Text>
            </UnstyledButton>
          ) : null}
        </Group>
      ) : null}
      <Box
        component="pre"
        ref={preRef}
        id={`${id}-code`}
        aria-label={language ?? 'Code'}
        m={0}
        px={14}
        py={12}
        style={{
          color: tokens.codeText,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
          fontSize: 12.5,
          lineHeight: 1.55,
          whiteSpace: wrap ? 'pre-wrap' : 'pre',
          overflowX: wrap ? 'hidden' : 'auto',
          overflowY: maxHeight ? 'auto' : 'visible',
          maxHeight,
          wordBreak: wrap ? 'break-word' : 'normal',
          tabSize: 2,
        }}
      >
        <code>{children}</code>
      </Box>
    </Box>
  );
}
