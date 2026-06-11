import React, { useState, useEffect } from 'react';
import { runSimulation, getScenarios } from '../../services/api';
import { Play, FlaskConical, AlertTriangle, Info } from 'lucide-react';

export default function Simulation() {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState('');
  const [targetIp, setTargetIp] = useState('10.0.0.5');
  const [intensity, setIntensity] = useState('1000');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);

  useEffect(() => {
    getScenarios().then(data => {
      setScenarios(data || []);
      if (data && data.length > 0) setSelectedScenario(data[0]);
    }).catch(console.error);
  }, []);

  const handleRun = async (e) => {
    e.preventDefault();
    try {
      setRunning(true);
      setResult(null);
      const res = await runSimulation(selectedScenario, {
        target_ip: targetIp,
        packet_count: parseInt(intensity)
      });
      setResult(res);
    } catch (err) {
      setResult({ error: err.response?.data?.error || err.message });
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 h-full flex flex-col">
      <div className="shrink-0">
        <h1 className="text-2xl font-bold text-white">Attack Simulation Lab</h1>
        <p className="text-dark-400 text-sm mt-1">Safely generate synthetic threat traffic to test detection engines.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1 min-h-0">
        
        {/* Controls */}
        <div className="bg-dark-900 border border-dark-800 rounded-xl p-6 overflow-y-auto">
          <div className="flex items-center space-x-2 mb-6">
            <FlaskConical className="w-5 h-5 text-primary-500" />
            <h2 className="text-lg font-medium text-white">Simulation Parameters</h2>
          </div>

          <form onSubmit={handleRun} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1">Scenario Type</label>
              <select 
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value)}
                className="w-full bg-dark-800 border border-dark-700 text-white rounded-lg px-4 py-2 focus:ring-1 focus:ring-primary-500"
                disabled={running}
              >
                {scenarios.map(s => <option key={s} value={s}>{s.replace('_', ' ').toUpperCase()}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1">Target IP Address</label>
              <input 
                type="text" 
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                className="w-full bg-dark-800 border border-dark-700 text-white rounded-lg px-4 py-2 focus:ring-1 focus:ring-primary-500 font-mono"
                placeholder="10.0.0.5"
                disabled={running}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1">Intensity (Packets)</label>
              <input 
                type="number" 
                value={intensity}
                onChange={(e) => setIntensity(e.target.value)}
                className="w-full bg-dark-800 border border-dark-700 text-white rounded-lg px-4 py-2 focus:ring-1 focus:ring-primary-500"
                min="100"
                max="10000"
                disabled={running}
              />
            </div>

            <div className="pt-4">
              <button 
                type="submit"
                disabled={running}
                className="w-full flex justify-center items-center px-4 py-3 bg-danger-600 hover:bg-danger-500 disabled:opacity-50 disabled:hover:bg-danger-600 text-white rounded-lg text-sm font-bold transition-colors"
              >
                {running ? (
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2"></div>
                ) : (
                  <Play className="w-5 h-5 mr-2 fill-current" />
                )}
                LAUNCH ATTACK SIMULATION
              </button>
            </div>
            
            <div className="mt-6 p-4 bg-warning-500/10 border border-warning-500/20 rounded-lg flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-warning-500 shrink-0 mt-0.5" />
              <p className="text-sm text-warning-400">
                This will inject synthetic packets directly into the packet processing pipeline. It may trigger real alerts and affect the network health score.
              </p>
            </div>
          </form>
        </div>

        {/* Results */}
        <div className="bg-dark-900 border border-dark-800 rounded-xl p-6 flex flex-col">
          <div className="flex items-center space-x-2 mb-6">
            <Info className="w-5 h-5 text-accent-500" />
            <h2 className="text-lg font-medium text-white">Execution Results</h2>
          </div>

          <div className="flex-1 bg-dark-950 border border-dark-800 rounded-lg p-4 font-mono text-sm overflow-y-auto whitespace-pre-wrap">
            {running ? (
              <span className="text-dark-400 animate-pulse">Running simulation...</span>
            ) : result ? (
              result.error ? (
                <span className="text-danger-500">Error: {result.error}</span>
              ) : (
                <span className="text-accent-400">{JSON.stringify(result, null, 2)}</span>
              )
            ) : (
              <span className="text-dark-500">Awaiting execution...</span>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
