import React, { useEffect, useState } from 'react';
import { getPredictions, triggerTraining } from '../../services/api';
import { LineChart, BrainCircuit, RefreshCw } from 'lucide-react';
import { format } from 'date-fns';

export default function Predictions() {
  const [predictions, setPredictions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [training, setTraining] = useState(false);

  useEffect(() => {
    fetchPredictions();
  }, []);

  const fetchPredictions = async () => {
    try {
      setLoading(true);
      const data = await getPredictions();
      setPredictions(data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleTrain = async () => {
    try {
      setTraining(true);
      await triggerTraining();
      await fetchPredictions();
    } catch (err) {
      console.error(err);
    } finally {
      setTraining(false);
    }
  };

  return (
    <div className="space-y-6 h-full flex flex-col">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white">ML Predictions</h1>
          <p className="text-dark-400 text-sm mt-1">Forecasted network events powered by Scikit-Learn.</p>
        </div>
        <button 
          onClick={handleTrain}
          disabled={training}
          className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium flex items-center transition-colors"
        >
          {training ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <BrainCircuit className="w-4 h-4 mr-2" />}
          Retrain Models
        </button>
      </div>

      <div className="flex-1 bg-dark-900 border border-dark-800 rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="overflow-x-auto flex-1">
          <table className="min-w-full divide-y divide-dark-800 relative">
            <thead className="bg-dark-900 sticky top-0 z-10 border-b border-dark-800">
              <tr>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Model Name</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Prediction Type</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Target Time</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Confidence</th>
                <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-dark-400 uppercase tracking-wider">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800/50">
              {loading && predictions.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center text-dark-400">Loading predictions...</td>
                </tr>
              ) : predictions.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center text-dark-400">No predictions generated yet.</td>
                </tr>
              ) : (
                predictions.map((pred) => (
                  <tr key={pred.id} className="hover:bg-dark-800/30 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white flex items-center">
                      <LineChart className="w-4 h-4 mr-2 text-primary-500" />
                      {pred.model_name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-dark-300 uppercase">
                      {pred.prediction_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-dark-300">
                      {pred.prediction_for ? format(new Date(pred.prediction_for), 'MMM d, HH:mm:ss') : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <span className="text-sm text-dark-300 w-12">{(pred.confidence * 100).toFixed(1)}%</span>
                        <div className="w-24 h-2 bg-dark-800 rounded-full ml-2 overflow-hidden">
                          <div 
                            className={`h-full rounded-full ${pred.confidence > 0.8 ? 'bg-accent-500' : pred.confidence > 0.5 ? 'bg-warning-500' : 'bg-danger-500'}`}
                            style={{ width: `${pred.confidence * 100}%` }}
                          ></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-dark-300">
                      {JSON.stringify(pred.prediction_data)}
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
