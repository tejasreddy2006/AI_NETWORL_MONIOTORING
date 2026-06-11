import React, { useEffect, useState } from 'react';
import { Bell, Search, Settings, Wifi, WifiOff } from 'lucide-react';
import { useSocket } from '../../contexts/SocketContext';
import { format } from 'date-fns';

export default function TopNav() {
  const { isConnected, latestHealth } = useSocket();
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const healthScore = latestHealth?.overall_score ?? 100;
  let healthColor = 'text-accent-500';
  if (healthScore < 50) healthColor = 'text-danger-500';
  else if (healthScore < 80) healthColor = 'text-warning-500';

  return (
    <div className="sticky top-0 z-10 flex h-16 flex-shrink-0 border-b border-dark-800 bg-dark-900/80 backdrop-blur-md">
      <div className="flex flex-1 items-center justify-between px-6">
        
        {/* Left side: Search & Status */}
        <div className="flex flex-1 items-center">
          <div className="flex w-full max-w-md items-center rounded-lg bg-dark-800 px-3 py-2 border border-dark-700 focus-within:border-primary-500 focus-within:ring-1 focus-within:ring-primary-500 transition-all duration-200">
            <Search className="h-5 w-5 text-dark-400" />
            <input
              type="text"
              placeholder="Search IP, device, or alert..."
              className="ml-2 block w-full border-0 bg-transparent text-sm text-white placeholder-dark-400 focus:ring-0"
            />
          </div>
        </div>

        {/* Right side: Connection, Time, Notifications */}
        <div className="ml-4 flex items-center space-x-6">
          
          {/* Health Score Mini */}
          <div className="hidden md:flex items-center space-x-2 border-r border-dark-700 pr-6">
            <span className="text-sm font-medium text-dark-300">System Health:</span>
            <span className={`text-lg font-bold ${healthColor}`}>
              {healthScore.toFixed(0)}%
            </span>
          </div>

          {/* Time */}
          <div className="hidden lg:block text-sm font-medium text-dark-300">
            {format(time, 'MMM d, yyyy HH:mm:ss')}
          </div>

          {/* Connection Status */}
          <div className="flex items-center space-x-2" title={isConnected ? 'Connected to Backend' : 'Disconnected'}>
            {isConnected ? (
              <Wifi className="h-5 w-5 text-accent-500" />
            ) : (
              <WifiOff className="h-5 w-5 text-danger-500 animate-pulse" />
            )}
          </div>

          {/* Actions */}
          <button className="relative rounded-full p-1 text-dark-400 hover:text-white hover:bg-dark-800 transition-colors">
            <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-danger-500 animate-pulse" />
            <Bell className="h-6 w-6" />
          </button>
          <button className="rounded-full p-1 text-dark-400 hover:text-white hover:bg-dark-800 transition-colors">
            <Settings className="h-6 w-6" />
          </button>
        </div>
      </div>
    </div>
  );
}
