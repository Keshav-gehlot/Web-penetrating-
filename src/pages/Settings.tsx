import React, { useState } from 'react';
import { Settings as SettingsIcon, Link2, Shield, Users, Bell, Key, Webhook } from 'lucide-react';
import { cn } from '../lib/utils';

export default function Settings() {
  const [activeTab, setActiveTab] = useState('integrations');

  return (
    <div className="flex flex-col h-full bg-phantom-bg">
      <div className="flex-none p-6 border-b border-phantom-border bg-phantom-surface/50 backdrop-blur-xl z-10 sticky top-0">
        <h1 className="text-xl font-semibold tracking-tight mb-6">Settings</h1>
        
        <div className="flex items-center gap-6">
          <button onClick={() => setActiveTab('general')} className={cn("text-sm font-medium pb-4 border-b-2 transition-colors", activeTab === 'general' ? "border-phantom-cyan text-phantom-text-primary" : "border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary")}>General</button>
          <button onClick={() => setActiveTab('team')} className={cn("text-sm font-medium pb-4 border-b-2 transition-colors", activeTab === 'team' ? "border-phantom-cyan text-phantom-text-primary" : "border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary")}>Team & Roles</button>
          <button onClick={() => setActiveTab('integrations')} className={cn("text-sm font-medium pb-4 border-b-2 transition-colors", activeTab === 'integrations' ? "border-phantom-cyan text-phantom-text-primary" : "border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary")}>Integrations</button>
          <button onClick={() => setActiveTab('api')} className={cn("text-sm font-medium pb-4 border-b-2 transition-colors", activeTab === 'api' ? "border-phantom-cyan text-phantom-text-primary" : "border-transparent text-phantom-text-tertiary hover:text-phantom-text-secondary")}>API Keys</button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-8">
        {activeTab === 'integrations' && (
          <div className="max-w-4xl max-w-full">
            <h2 className="text-lg font-medium text-phantom-text-primary mb-2">Connected Services</h2>
            <p className="text-sm text-phantom-text-secondary mb-8">Connect Phantom to your existing workflow and alerting tools.</p>
            
            <div className="space-y-4">
              <IntegrationCard 
                title="Slack" 
                desc="Send scan completion alerts and critical vulnerability notifications to #security channels." 
                icon={Webhook} 
                status="connected" 
              />
              <IntegrationCard 
                title="Jira Software" 
                desc="Automatically create and assign Jira tickets when high-severity vulnerabilities are found." 
                icon={Link2} 
                status="configured" 
              />
              <IntegrationCard 
                title="GitHub" 
                desc="Scan repositories directly and create PRs for dependency updates." 
                icon={Key} 
                status="disconnected" 
              />
              <IntegrationCard 
                title="PagerDuty" 
                desc="Trigger incidents for severity critical findings immediately." 
                icon={Bell} 
                status="disconnected" 
              />
            </div>
          </div>
        )}

        {activeTab !== 'integrations' && (
          <div className="max-w-4xl text-phantom-text-secondary text-sm">
             Configuration options for {activeTab} will appear here.
          </div>
        )}
      </div>
    </div>
  );
}

function IntegrationCard({ title, desc, icon: Icon, status }: any) {
  return (
    <div className="p-5 border border-phantom-border rounded-xl bg-phantom-surface flex items-start gap-4 hover:border-phantom-border-strong transition-colors">
      <div className="w-12 h-12 rounded-lg bg-phantom-panel flex items-center justify-center text-phantom-text-primary shadow-sm border border-phantom-border">
         <Icon size={24} />
      </div>
      <div className="flex-1">
         <div className="flex items-center justify-between mb-1">
            <h3 className="font-medium text-phantom-text-primary">{title}</h3>
            {status === 'connected' ? (
              <span className="px-2 py-1 bg-phantom-cyan/10 text-phantom-cyan text-xs font-medium rounded border border-phantom-cyan/20">Connected</span>
            ) : status === 'configured' ? (
              <span className="px-2 py-1 bg-phantom-amber/10 text-phantom-amber text-xs font-medium rounded border border-phantom-amber/20">Needs Auth</span>
            ) : (
              <span className="px-2 py-1 bg-phantom-panel text-phantom-text-tertiary text-xs font-medium rounded border border-phantom-border">Disconnected</span>
            )}
         </div>
         <p className="text-sm text-phantom-text-secondary mb-4">{desc}</p>
         
         <div className="flex gap-2">
            <button className={cn(
              "px-4 py-1.5 rounded-md text-sm font-medium transition-opacity",
              status === 'connected' 
                ? "bg-phantom-panel border border-phantom-border text-phantom-text-secondary hover:text-phantom-text-primary" 
                : "bg-phantom-text-primary text-black hover:opacity-90"
            )}>
              {status === 'connected' ? 'Configure' : 'Connect'}
            </button>
         </div>
      </div>
    </div>
  );
}
