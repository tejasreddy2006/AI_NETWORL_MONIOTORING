import React, { createContext, useContext, useEffect, useState } from 'react';
import { socket, connectSocket, disconnectSocket } from '../services/socket';

const SocketContext = createContext(null);

export const useSocket = () => useContext(SocketContext);

export const SocketProvider = ({ children }) => {
  const [isConnected, setIsConnected] = useState(socket.connected);
  const [latestPacket, setLatestPacket] = useState(null);
  const [latestAlert, setLatestAlert] = useState(null);
  const [latestHealth, setLatestHealth] = useState(null);

  useEffect(() => {
    connectSocket();

    const onConnect = () => setIsConnected(true);
    const onDisconnect = () => setIsConnected(false);
    const onNewPacket = (data) => setLatestPacket(data);
    const onNewAlert = (data) => setLatestAlert(data);
    const onHealthUpdate = (data) => setLatestHealth(data);

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('packet:new', onNewPacket);
    socket.on('alert:new', onNewAlert);
    socket.on('health:update', onHealthUpdate);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('packet:new', onNewPacket);
      socket.off('alert:new', onNewAlert);
      socket.off('health:update', onHealthUpdate);
      disconnectSocket();
    };
  }, []);

  return (
    <SocketContext.Provider
      value={{
        socket,
        isConnected,
        latestPacket,
        latestAlert,
        latestHealth,
      }}
    >
      {children}
    </SocketContext.Provider>
  );
};
