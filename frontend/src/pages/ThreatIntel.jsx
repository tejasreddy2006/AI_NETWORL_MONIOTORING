import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { getThreatMap } from '../../services/api';
import L from 'leaflet';

// Fix for default marker icons in React Leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

export default function ThreatIntel() {
  const [mapData, setMapData] = useState([]);

  useEffect(() => {
    getThreatMap().then(data => {
      setMapData(data || []);
    }).catch(console.error);
  }, []);

  return (
    <div className="space-y-6 h-full flex flex-col">
      <div className="shrink-0">
        <h1 className="text-2xl font-bold text-white">Global Threat Intelligence</h1>
        <p className="text-dark-400 text-sm mt-1">Geographic distribution of suspicious network traffic.</p>
      </div>

      <div className="flex-1 bg-dark-900 border border-dark-800 rounded-xl overflow-hidden min-h-[400px] relative z-0">
        <MapContainer 
          center={[20, 0]} 
          zoom={2} 
          style={{ height: '100%', width: '100%', background: '#0f172a' }}
          worldCopyJump={true}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          {mapData.map((node, i) => (
            <CircleMarker 
              key={i}
              center={[node.latitude, node.longitude]} 
              radius={Math.max(5, Math.min(20, node.packet_count / 100))}
              fillColor={node.reputation_score < 30 ? "#ef4444" : "#f59e0b"}
              color={node.reputation_score < 30 ? "#7f1d1d" : "#78350f"}
              weight={2}
              opacity={1}
              fillOpacity={0.6}
            >
              <Popup className="bg-dark-900 border-dark-800 text-dark-100">
                <div className="p-1">
                  <h3 className="font-bold text-dark-900 border-b pb-1 mb-1">{node.ip_address}</h3>
                  <p className="text-sm text-dark-800"><strong>Country:</strong> {node.country_name}</p>
                  <p className="text-sm text-dark-800"><strong>Packets:</strong> {node.packet_count}</p>
                  <p className="text-sm text-dark-800"><strong>Reputation:</strong> {node.reputation_score.toFixed(1)}/100</p>
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}
