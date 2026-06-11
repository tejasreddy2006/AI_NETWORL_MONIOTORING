import React, { useEffect, useState, useCallback } from 'react';
import ReactFlow, { 
  MiniMap, 
  Controls, 
  Background, 
  useNodesState, 
  useEdgesState,
  MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import { getTopology } from '../../services/api';
import { Server, Monitor, Router as RouterIcon, AlertTriangle } from 'lucide-react';

const nodeTypes = {}; // custom node types can be added here if needed

export default function Topology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);

  const fetchGraph = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getTopology();
      // Translate backend topology format to ReactFlow format
      
      const rfNodes = (data.nodes || []).map((node, i) => {
        // Simple layout: circle arrangement if no coords provided
        const angle = (i / (data.nodes.length || 1)) * 2 * Math.PI;
        const radius = 250;
        
        let bgColor = '#1e293b'; // dark-800
        let borderColor = '#334155'; // dark-700
        
        if (node.health_status === 'CRITICAL') {
          borderColor = '#ef4444'; // danger-500
          bgColor = '#450a0a'; // danger-950
        } else if (node.health_status === 'WARNING') {
          borderColor = '#f59e0b'; // warning-500
          bgColor = '#451a03'; // warning-950
        } else if (node.health_status === 'HEALTHY') {
          borderColor = '#10b981'; // accent-500
        }

        return {
          id: node.id.toString(),
          position: { x: 400 + radius * Math.cos(angle), y: 300 + radius * Math.sin(angle) },
          data: { 
            label: (
              <div className="flex flex-col items-center justify-center p-2">
                {node.device_type === 'router' ? <RouterIcon className="w-6 h-6 mb-1 text-dark-300" /> :
                 node.device_type === 'server' ? <Server className="w-6 h-6 mb-1 text-dark-300" /> :
                 <Monitor className="w-6 h-6 mb-1 text-dark-300" />}
                <span className="font-bold text-xs text-white">{node.ip_address}</span>
                {node.hostname && <span className="text-[10px] text-dark-400">{node.hostname}</span>}
              </div>
            )
          },
          style: {
            background: bgColor,
            border: `2px solid ${borderColor}`,
            borderRadius: '8px',
            color: '#fff',
            width: 120,
          }
        };
      });

      const rfEdges = (data.edges || []).map(edge => ({
        id: `e${edge.source}-${edge.target}`,
        source: edge.source.toString(),
        target: edge.target.toString(),
        animated: edge.packet_count > 1000,
        style: { stroke: '#475569', strokeWidth: Math.min(max_width=4, edge.packet_count / 1000 + 1) },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#475569',
        },
      }));

      setNodes(rfNodes);
      setEdges(rfEdges);
    } catch (err) {
      console.error("Failed to load topology", err);
    } finally {
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  return (
    <div className="h-full flex flex-col space-y-4">
      <div className="flex justify-between items-center shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Topology</h1>
          <p className="text-dark-400 text-sm mt-1">Automatically discovered devices and traffic links.</p>
        </div>
        <button 
          onClick={fetchGraph}
          className="px-4 py-2 bg-dark-800 hover:bg-dark-700 text-white rounded-lg text-sm font-medium transition-colors border border-dark-700"
        >
          Refresh Map
        </button>
      </div>

      <div className="flex-1 bg-dark-900 border border-dark-800 rounded-xl overflow-hidden relative">
        {loading && (
          <div className="absolute inset-0 z-10 bg-dark-900/50 backdrop-blur-sm flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
          </div>
        )}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          attributionPosition="bottom-right"
        >
          <Background color="#334155" gap={16} />
          <Controls className="bg-dark-800 border-dark-700 fill-white" />
        </ReactFlow>
      </div>
    </div>
  );
}
