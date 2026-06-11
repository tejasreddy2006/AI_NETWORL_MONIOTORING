import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { SocketProvider } from './contexts/SocketContext';

import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import RealTimeMonitor from './pages/RealTimeMonitor';
import Topology from './pages/Topology';
import AlertCenter from './pages/AlertCenter';
import ThreatIntel from './pages/ThreatIntel';
import Predictions from './pages/Predictions';
import Health from './pages/Health';
import Simulation from './pages/Simulation';
import AICopilot from './pages/AICopilot';

function App() {
  return (
    <SocketProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="monitor" element={<RealTimeMonitor />} />
            <Route path="topology" element={<Topology />} />
            <Route path="alerts" element={<AlertCenter />} />
            <Route path="threats" element={<ThreatIntel />} />
            <Route path="predictions" element={<Predictions />} />
            <Route path="health" element={<Health />} />
            <Route path="simulation" element={<Simulation />} />
            <Route path="copilot" element={<AICopilot />} />
          </Route>
        </Routes>
      </Router>
    </SocketProvider>
  );
}

export default App;
