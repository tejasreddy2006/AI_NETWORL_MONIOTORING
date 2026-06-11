import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Activity, 
  Network, 
  ShieldAlert, 
  Globe, 
  LineChart, 
  HeartPulse, 
  FlaskConical, 
  MessageSquareCode
} from 'lucide-react';
import { cn } from '../../utils/cn';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Real-time Monitor', href: '/monitor', icon: Activity },
  { name: 'Network Topology', href: '/topology', icon: Network },
  { name: 'Alert Center', href: '/alerts', icon: ShieldAlert },
  { name: 'Threat Intel', href: '/threats', icon: Globe },
  { name: 'ML Predictions', href: '/predictions', icon: LineChart },
  { name: 'Network Health', href: '/health', icon: HeartPulse },
  { name: 'Simulation Lab', href: '/simulation', icon: FlaskConical },
  { name: 'AI Copilot', href: '/copilot', icon: MessageSquareCode },
];

export default function Sidebar() {
  return (
    <div className="flex h-full w-64 flex-col bg-dark-900 border-r border-dark-800">
      <div className="flex h-16 shrink-0 items-center px-6 border-b border-dark-800">
        <ShieldAlert className="h-8 w-8 text-primary-500 mr-3" />
        <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary-400 to-accent-400">
          NetGuard AI
        </span>
      </div>
      <div className="flex flex-1 flex-col overflow-y-auto pt-5 pb-4">
        <nav className="flex-1 space-y-1 px-3">
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                cn(
                  isActive
                    ? 'bg-dark-800 text-white'
                    : 'text-dark-300 hover:bg-dark-800/50 hover:text-white',
                  'group flex items-center rounded-md px-3 py-2 text-sm font-medium transition-all duration-200'
                )
              }
            >
              {({ isActive }) => (
                <>
                  <item.icon
                    className={cn(
                      isActive ? 'text-primary-400' : 'text-dark-400 group-hover:text-primary-400',
                      'mr-3 h-5 w-5 flex-shrink-0 transition-colors duration-200'
                    )}
                    aria-hidden="true"
                  />
                  {item.name}
                </>
              )}
            </NavLink>
          ))}
        </nav>
      </div>
      <div className="p-4 border-t border-dark-800">
        <div className="flex items-center">
          <div className="h-8 w-8 rounded-full bg-gradient-to-r from-primary-600 to-accent-600 flex items-center justify-center text-white font-bold text-sm">
            CG
          </div>
          <div className="ml-3">
            <p className="text-sm font-medium text-white">System Admin</p>
            <p className="text-xs text-dark-400">NetGuard Ops</p>
          </div>
        </div>
      </div>
    </div>
  );
}
