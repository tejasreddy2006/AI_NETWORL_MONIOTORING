import React, { useEffect, useState } from 'react';
import { useSocket } from '../../contexts/SocketContext';
import { getHealthScore, getAlerts } from '../../services/api';
import { ShieldAlert, Activity, ArrowUpRight, Server, Network } from 'lucide-react';
import { format } from 'date-fns';

function StatCard({ title, value, icon: Icon, trend, colorClass }) {
  return (
    <div className="bg-dark-900 border border-dark-800 rounded-xl p-6 relative overflow-hidden group">
      <div className={`absolute top-0 right-0 p-4 opacity-10 transition-opacity group-hover:opacity-20 ${colorClass}`}>
        <Icon className="w-16 h-16" />
      </div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-dark-300 font-medium text-sm">{title}</h3>
        <div className={`p-2 rounded-lg bg-dark-800 ${colorClass}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="flex items-baseline space-x-2">
        <h2 className="text-3xl font-bold text-white">{value}</h2>
        {trend && (
          <span className="flex items-center text-xs font-medium text-accent-500">
            {trend}
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </span>
        )}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { latestHealth, latestPacket, latestAlert } = useSocket();
  const [stats, setStats] = useState({
    healthScore: 100,
    activeThreats: 0,
    devices: 0,
    trafficRate: 0,
  });
  const [recentAlerts, setRecentAlerts] = useState([]);

  useEffect(() => {
    // Initial fetch
    getHealthScore().then(data => {
      setStats(s => ({ ...s, healthScore: data.overall_score || 100 }));
    }).catch(console.error);

    getAlerts({ per_page: 5 }).then(data => {
      setRecentAlerts(data.alerts || []);
      setStats(s => ({ ...s, activeThreats: data.total || 0 }));
    }).catch(console.error);
  }, []);

  // Update from socket events
  useEffect(() => {
    if (latestHealth) {
      setStats(s => ({ ...s, healthScore: latestHealth.overall_score }));
    }
  }, [latestHealth]);

  useEffect(() => {
    if (latestAlert) {
      setRecentAlerts(prev => [latestAlert, ...prev].slice(0, 5));
      setStats(s => ({ ...s, activeThreats: s.activeThreats + 1 }));
    }
  }, [latestAlert]);

  useEffect(() => {
    if (latestPacket) {
      // Very basic pseudo-rate calculation just for demo visual changes
      setStats(s => ({ ...s, trafficRate: Math.floor(Math.random() * 500) + 100 }));
    }
  }, [latestPacket]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Network Dashboard</h1>
        <p className="text-dark-400 text-sm mt-1">Real-time overview of network health and security events.</p>
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard 
          title="Network Health" 
          value={`${stats.healthScore.toFixed(0)}%`} 
          icon={Activity} 
          colorClass={stats.healthScore > 80 ? "text-accent-500" : stats.healthScore > 50 ? "text-warning-500" : "text-danger-500"} 
        />
        <StatCard 
          title="Active Threats" 
          value={stats.activeThreats} 
          icon={ShieldAlert} 
          trend="+2 recent"
          colorClass="text-danger-500" 
        />
        <StatCard 
          title="Traffic Rate" 
          value={`${stats.trafficRate} Mbps`} 
          icon={Network} 
          trend="Live"
          colorClass="text-primary-500" 
        />
        <StatCard 
          title="Monitored Devices" 
          value="42" 
          icon={Server} 
          colorClass="text-dark-300" 
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Recent Alerts Panel */}
        <div className="lg:col-span-2 bg-dark-900 border border-dark-800 rounded-xl flex flex-col">
          <div className="px-6 py-4 border-b border-dark-800 flex justify-between items-center">
            <h3 className="text-lg font-medium text-white">Recent Security Alerts</h3>
            <button className="text-sm text-primary-400 hover:text-primary-300">View All</button>
          </div>
          <div className="flex-1 p-0 overflow-auto">
            {recentAlerts.length === 0 ? (
              <div className="flex items-center justify-center h-48 text-dark-400">
                No recent alerts detected.
              </div>
            ) : (
              <ul className="divide-y divide-dark-800">
                {recentAlerts.map(alert => (
                  <li key={alert.id} className="px-6 py-4 hover:bg-dark-800/50 transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-4">
                        <div className={`p-2 rounded-full ${
                          alert.severity === 'CRITICAL' ? 'bg-danger-500/20 text-danger-500' :
                          alert.severity === 'HIGH' ? 'bg-warning-500/20 text-warning-500' :
                          'bg-dark-700 text-dark-300'
                        }`}>
                          <ShieldAlert className="w-5 h-5" />
                        </div>
                        <div>
                          <p className="text-sm font-medium text-white">{alert.threat_type}</p>
                          <p className="text-xs text-dark-400 mt-1">{alert.source_ip} → {alert.destination_ip}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${
                          alert.severity === 'CRITICAL' ? 'bg-danger-500/10 text-danger-400 border border-danger-500/20' :
                          alert.severity === 'HIGH' ? 'bg-warning-500/10 text-warning-400 border border-warning-500/20' :
                          'bg-dark-800 text-dark-300'
                        }`}>
                          {alert.severity}
                        </span>
                        <p className="text-xs text-dark-500 mt-2">
                          {alert.timestamp ? format(new Date(alert.timestamp), 'HH:mm:ss') : 'Just now'}
                        </p>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Quick Actions / Status */}
        <div className="bg-dark-900 border border-dark-800 rounded-xl p-6">
          <h3 className="text-lg font-medium text-white mb-4">System Status</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-dark-800 rounded-lg border border-dark-700">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-accent-500 rounded-full animate-pulse mr-3"></div>
                <span className="text-sm font-medium text-dark-100">Packet Sniffer</span>
              </div>
              <span className="text-xs text-accent-500 bg-accent-500/10 px-2 py-1 rounded">Active</span>
            </div>
            <div className="flex items-center justify-between p-4 bg-dark-800 rounded-lg border border-dark-700">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-accent-500 rounded-full animate-pulse mr-3"></div>
                <span className="text-sm font-medium text-dark-100">AI Copilot</span>
              </div>
              <span className="text-xs text-accent-500 bg-accent-500/10 px-2 py-1 rounded">Online</span>
            </div>
            <div className="flex items-center justify-between p-4 bg-dark-800 rounded-lg border border-dark-700">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-accent-500 rounded-full animate-pulse mr-3"></div>
                <span className="text-sm font-medium text-dark-100">ML Engine</span>
              </div>
              <span className="text-xs text-accent-500 bg-accent-500/10 px-2 py-1 rounded">Ready</span>
            </div>
          </div>
        </div>
        
      </div>
    </div>
  );
}
