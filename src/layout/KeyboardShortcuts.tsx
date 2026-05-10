import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Command } from 'lucide-react';

const SHORTCUTS = [
  { keys: ['G', 'D'], action: 'Go to Dashboard' },
  { keys: ['G', 'V'], action: 'Go to Vulnerabilities' },
  { keys: ['G', 'S'], action: 'Go to Scans' },
  { keys: ['G', 'R'], action: 'Go to Reports' },
  { keys: ['S'], action: 'Start New Scan' },
  { keys: ['/'], action: 'Global Search' },
  { keys: ['⌘', 'K'], action: 'Command Palette' },
  { keys: ['?'], action: 'Toggle Shortcuts' },
];

export function KeyboardShortcuts() {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if input is focused
      if (['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement).tagName)) return;
      
      if (e.key === '?') {
        e.preventDefault();
        setIsOpen((open) => !open);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-phantom-bg/80 backdrop-blur-sm z-[100] transition-opacity"
            onClick={() => setIsOpen(false)}
          />
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ type: 'spring', stiffness: 400, damping: 30 }}
              className="w-full max-w-lg bg-phantom-panel border border-phantom-border rounded-xl shadow-2xl overflow-hidden pointer-events-auto"
            >
              <div className="flex items-center gap-3 px-6 py-4 border-b border-phantom-border bg-phantom-surface">
                <div className="p-2 rounded bg-phantom-bg border border-phantom-border">
                  <Command size={16} className="text-phantom-text-primary" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-phantom-text-primary">Keyboard Shortcuts</h2>
                  <p className="text-xs text-phantom-text-tertiary">Navigate Phantom like a pro</p>
                </div>
              </div>
              
              <div className="p-4 grid grid-cols-2 gap-x-8 gap-y-2 max-h-[60vh] overflow-y-auto">
                {SHORTCUTS.map((shortcut, i) => (
                  <div key={i} className="flex items-center justify-between py-2 border-b border-phantom-border/50 last:border-0">
                    <span className="text-sm text-phantom-text-secondary">{shortcut.action}</span>
                    <div className="flex gap-1">
                      {shortcut.keys.map((key, j) => (
                        <kbd key={j} className="px-2 py-1 rounded bg-phantom-surface border border-phantom-border text-xs font-mono text-phantom-text-primary shadow-sm min-w-[24px] text-center">
                          {key}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="px-6 py-3 border-t border-phantom-border bg-phantom-surface flex justify-between items-center text-xs text-phantom-text-tertiary">
                 <span>Press <kbd>Esc</kbd> to close</span>
                 <span>Phantom UI Framework</span>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
