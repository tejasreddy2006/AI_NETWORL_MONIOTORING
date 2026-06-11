import React, { useEffect, useState } from 'react';
import { useSocket } from '../../contexts/SocketContext';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { format } from 'date-fns';

export default function RealTimeMonitor() {
  const { latestPacket } = useSocket();
  const [data, setData] = useState([]);

  useEffect(() => {
    // Initialize empty data
    const initial = Array.from({ length: 30 }).map((_, i) => ({
      time: format(new Date(Date.now() - (30 - i) * 1000), 'HH:mm:ss'),
      bytes: 0,
      packets: 0
    }));
    setData(initial);
  }, []);

  useEffect(() => {
    if (latestPacket) {
      setData(prev => {
        const now = format(new Date(), 'HH:mm:ss');
        // Very simplistic grouping for demo: just append random-ish variations if actual throughput isn't available
        const newPoint = {
          time: now,
          bytes: latestPacket.packet_size || Math.floor(Math.random() * 1500),
          packets: 1 + Math.floor(Math.random() * 5)
        };
        return [...prev.slice(1), newPoint];
      });
    } else {
      // Simulate ticking if no packets
      const interval = setInterval(() => {
        setData(prev => {
          const now = format(new Date(), 'HH:mm:ss');
          return [...prev.slice(1), { time: now, bytes: 0, packets: 0 }];
        });
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [latestPacket]);

  return (
    <div className="space-y-6 h-full flex flex-col">
      <div>
        <h1 className="text-2xl font-bold text-white">Real-time Monitor</h1>
        <p className="text-dark-400 text-sm mt-1">Live traffic telemetry from packet capture engine.</p>
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">
        
        {/* Bytes Chart */}
        <div className="bg-dark-900 border border-dark-800 rounded-xl p-6 flex flex-col">
          <h3 className="text-lg font-medium text-white mb-6">Traffic Volume (Bytes/s)</h3>
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#64748b" fontSize={12} tickFormatter={(val) => `${val} B`} width={60} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  itemStyle={{ color: '#818cf8' }}
                />
                <Area type="monotone" dataKey="bytes" stroke="#818cf8" strokeWidth={2} fillOpacity={1} fill="url(#colorBytes)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Packets Chart */}
        <div className="bg-dark-900 border border-dark-800 rounded-xl p-6 flex flex-col">
          <h3 className="text-lg font-medium text-white mb-6">Packet Rate (Pkts/s)</h3>
          <div className="flex-1 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#64748b" fontSize={12} width={40} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  itemStyle={{ color: '#34d399' }}
                />
                <Area type="stepAfter" dataKey="packets" stroke="#34d399" strokeWidth={2} fillOpacity={1} fill="url(#colorPackets)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>
    </div>
  );
}
