import React, { useEffect, useState } from 'react';
import { getAlerts, resolveAlert } from '../../services/api';
import { format } from 'date-fns';
import { ShieldAlert, CheckCircle, Search, Filter } from 'lucide-react';

export default function AlertCenter() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL'); // ALL, UNRESOLVED, CRITICAL

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const data = await getAlerts({ per_page: 100 });
      setAlerts(data.alerts || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async (id) => {
    try {
      await resolveAlert(id);
      setAlerts(alerts.map(a => a.id === id ? { ...a, is_resolved: true } : a));
    } catch (err) {
      console.error(err);
    }
  };

  const filteredAlerts = alerts.filter(a => {
    if (filter === 'UNRESOLVED') return !a.is_resolved;
    if (filter === 'CRITICAL') return a.severity === 'CRITICAL';
    return true;
  });

  return (
    <div className="space-y-6 h-full flex flex-col">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white">Alert Center</h1>
          <p className="text-dark-400 text-sm mt-1">Investigate and resolve security threats.</p>
        </div>
        <div className="flex space-x-2">
          <select 
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-dark-800 border border-dark-700 text-white rounded-lg px-4 py-2 text-sm focus:ring-1 focus:ring-primary-500"
          >
            <option value="ALL">All Alerts</option>
            <option value="UNRESOLVED">Unresolved Only</option>
            <option value="CRITICAL">Critical Severity</option>
          </select>
          <button onClick={fetchAlerts} className="px-4 py-2 bg-dark-800 hover:bg-dark-700 text-white rounded-lg text-sm font-medium border border-dark-700">
            Refresh
          </button>
        </div>
      </div>

      <div className="flex-1 bg-dark-900 border border-dark-800 rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="overflow-x-auto flex-1">
          <table className="min-w-full divide-y divide-dark-800 relative">
            <thead className="bg-dark-900 sticky top-0 z-10 border-b border-dark-800">
              <tr>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Status</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Time</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Severity</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Threat Type</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Source</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Destination</th>
                <th scope="col" className="px-6 py-4 text-right text-xs font-medium text-dark-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800/50 bg-transparent">
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-6 py-12 text-center text-dark-400">Loading alerts...</td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-6 py-12 text-center text-dark-400">No alerts found matching criteria.</td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-dark-800/30 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      {alert.is_resolved ? (
                        <CheckCircle className="w-5 h-5 text-accent-500" />
                      ) : (
                        <ShieldAlert className={`w-5 h-5 ${alert.severity === 'CRITICAL' ? 'text-danger-500 animate-pulse' : 'text-warning-500'}`} />
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-dark-300">
                      {format(new Date(alert.timestamp), 'MMM d, HH:mm:ss')}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                        alert.severity === 'CRITICAL' ? 'bg-danger-500/10 text-danger-400 border border-danger-500/20' :
                        alert.severity === 'HIGH' ? 'bg-warning-500/10 text-warning-400 border border-warning-500/20' :
                        alert.severity === 'MEDIUM' ? 'bg-primary-500/10 text-primary-400 border border-primary-500/20' :
                        'bg-dark-800 text-dark-300'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                      {alert.threat_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-dark-300 font-mono">
                      {alert.source_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-dark-300 font-mono">
                      {alert.destination_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      {!alert.is_resolved && (
                        <button
                          onClick={() => handleResolve(alert.id)}
                          className="text-accent-500 hover:text-accent-400 bg-accent-500/10 px-3 py-1 rounded transition-colors"
                        >
                          Resolve
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
