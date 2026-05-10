import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Search, Terminal, ArrowRight } from 'lucide-react';

export function CommandPalette() {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setIsOpen((open) => !open);
      }
    };

    document.addEventListener('keydown', down);
    return () => document.removeEventListener('keydown', down);
  }, []);

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-phantom-bg/80 backdrop-blur-sm z-50 transition-opacity"
            onClick={() => setIsOpen(false)}
          />
          <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: -20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -20 }}
              transition={{ type: "spring", stiffness: 400, damping: 30 }}
              className="w-full max-w-2xl bg-phantom-panel border border-phantom-border rounded-xl shadow-2xl overflow-hidden pointer-events-auto"
            >
              <div className="flex items-center px-4 py-3 border-b border-phantom-border">
                <Search className="text-phantom-text-tertiary mr-3" size={20} />
                <input
                  type="text"
                  autoFocus
                  placeholder="Type a command or search..."
                  className="flex-1 bg-transparent border-none outline-none text-phantom-text-primary text-lg placeholder:text-phantom-text-tertiary"
                />
                <div className="flex items-center gap-1 text-xs text-phantom-text-tertiary font-mono">
                  <span className="px-1.5 py-0.5 rounded bg-phantom-surface border border-phantom-border">esc</span>
                  <span>to close</span>
                </div>
              </div>
              
              <div className="p-2 max-h-[60vh] overflow-y-auto">
                <div className="px-3 py-2 text-xs font-semibold text-phantom-text-tertiary uppercase tracking-wider">Suggestions</div>
                <div className="space-y-1">
                  <PaletteItem icon={Terminal} label="Start new scan" shortcut="S" />
                  <PaletteItem icon={ArrowRight} label="Go to Assets" shortcut="G A" />
                  <PaletteItem icon={ArrowRight} label="Go to Vulnerabilities" shortcut="G V" />
                </div>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}

function PaletteItem({ icon: Icon, label, shortcut }: any) {
  return (
    <button className="w-full flex items-center justify-between px-3 py-2.5 rounded-lg hover:bg-phantom-surface text-phantom-text-secondary hover:text-phantom-text-primary transition-colors text-left group">
      <div className="flex items-center gap-3">
        <Icon size={16} className="text-phantom-text-tertiary group-hover:text-phantom-cyan transition-colors" />
        <span className="font-medium text-sm">{label}</span>
      </div>
      {shortcut && (
        <div className="flex items-center gap-1">
          {shortcut.split(' ').map((key: string, i: number) => (
             <span key={i} className="px-1.5 py-0.5 rounded bg-phantom-bg border border-phantom-border text-[10px] font-mono text-phantom-text-tertiary uppercase">
               {key}
             </span>
          ))}
        </div>
      )}
    </button>
  );
}
