import React, { useEffect, useState } from 'react';
import { getHealthHistory } from '../../services/api';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { format } from 'date-fns';

export default function Health() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getHealthHistory().then(data => {
      // Sort ascending by time for the chart
      const sorted = (data || []).sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      const formatted = sorted.map(d => ({
        ...d,
        time: format(new Date(d.created_at), 'HH:mm'),
        // Scale some metrics up to 100 for better unified visualization
        trafficScore: d.traffic_stability * 100,
        deviceScore: d.device_availability * 100,
      }));
      setHistory(formatted);
    }).catch(console.error).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6 h-full flex flex-col">
      <div className="shrink-0">
        <h1 className="text-2xl font-bold text-white">Network Health</h1>
        <p className="text-dark-400 text-sm mt-1">Historical tracking of system health metrics.</p>
      </div>

      <div className="flex-1 bg-dark-900 border border-dark-800 rounded-xl p-6 min-h-[400px]">
        {loading ? (
          <div className="h-full flex items-center justify-center text-dark-400">Loading health data...</div>
        ) : history.length === 0 ? (
          <div className="h-full flex items-center justify-center text-dark-400">No historical data available.</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickMargin={10} />
              <YAxis yAxisId="left" stroke="#64748b" fontSize={12} domain={[0, 100]} />
              <YAxis yAxisId="right" orientation="right" stroke="#64748b" fontSize={12} domain={[0, 'auto']} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
              />
              <Legend wrapperStyle={{ paddingTop: '20px' }} />
              
              {/* Primary metrics (0-100 scale) */}
              <Line yAxisId="left" type="monotone" name="Overall Score" dataKey="overall_score" stroke="#6366f1" strokeWidth={3} dot={false} />
              <Line yAxisId="left" type="monotone" name="Traffic Stability" dataKey="trafficScore" stroke="#34d399" strokeWidth={2} strokeDasharray="5 5" dot={false} />
              <Line yAxisId="left" type="monotone" name="Device Availability" dataKey="deviceScore" stroke="#f59e0b" strokeWidth={2} strokeDasharray="5 5" dot={false} />
              
              {/* Secondary metrics (variable scale) */}
              <Line yAxisId="right" type="monotone" name="Alert Frequency" dataKey="alert_frequency" stroke="#ef4444" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
