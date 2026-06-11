import React, { useState, useEffect, useRef } from 'react';
import { chatAi } from '../../services/api';
import { useSocket } from '../../contexts/SocketContext';
import { Send, User, Bot, AlertCircle } from 'lucide-react';
import { format } from 'date-fns';

export default function AICopilot() {
  const { isConnected } = useSocket();
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hello! I am NetGuard AI Copilot. I can analyse recent alerts, look up IP reputations, or provide network health summaries. How can I help you today?', timestamp: new Date() }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId] = useState(() => 'sess-' + Math.random().toString(36).substr(2, 9));
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMsg = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMsg, timestamp: new Date() }]);
    setLoading(true);

    try {
      const data = await chatAi(sessionId, userMsg);
      setMessages(prev => [...prev, { role: 'assistant', content: data.response || data, timestamp: new Date() }]);
    } catch (err) {
      console.error(err);
      setMessages(prev => [...prev, { role: 'assistant', content: "Sorry, I encountered an error communicating with the backend. Ensure the LLM provider is configured or the fallback assistant is active.", error: true, timestamp: new Date() }]);
    } finally {
      setLoading(false);
    }
  };

  // Simple Markdown renderer for the chat
  const renderMarkdown = (text) => {
    if (!text) return null;
    
    // Split by newlines and render paragraphs/tables roughly
    const lines = text.split('\n');
    let inTable = false;
    
    return lines.map((line, i) => {
      // Headers
      if (line.startsWith('## ')) return <h2 key={i} className="text-lg font-bold text-white mt-4 mb-2">{line.replace('## ', '')}</h2>;
      if (line.startsWith('### ')) return <h3 key={i} className="text-md font-bold text-white mt-3 mb-1">{line.replace('### ', '')}</h3>;
      
      // Bold
      let formattedLine = line;
      formattedLine = formattedLine.replace(/\*\*(.*?)\*\*/g, '<span class="font-bold text-white">$1</span>');
      
      // Code blocks (single line inline code)
      formattedLine = formattedLine.replace(/`([^`]+)`/g, '<code class="bg-dark-800 text-primary-400 px-1 py-0.5 rounded text-sm">$1</code>');

      // Lists
      if (line.startsWith('- ')) {
        return <li key={i} className="ml-4 list-disc text-dark-200 my-1" dangerouslySetInnerHTML={{ __html: formattedLine.substring(2) }} />;
      }
      
      // Tables (very basic)
      if (line.startsWith('|')) {
        const cells = formattedLine.split('|').filter(c => c.trim());
        if (line.includes('---')) return null; // skip separator
        return (
          <div key={i} className="flex border-b border-dark-700 bg-dark-800/50 p-1">
            {cells.map((cell, j) => (
              <div key={j} className="flex-1 px-2 text-sm" dangerouslySetInnerHTML={{ __html: cell }} />
            ))}
          </div>
        );
      }
      
      if (line.trim() === '') return <br key={i} />;
      
      return <p key={i} className="text-dark-200 my-1" dangerouslySetInnerHTML={{ __html: formattedLine }} />;
    });
  };

  return (
    <div className="h-full flex flex-col space-y-4 max-w-5xl mx-auto">
      <div className="shrink-0 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">AI Copilot</h1>
          <p className="text-dark-400 text-sm mt-1">Conversational assistant for network security analysis.</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-accent-500' : 'bg-danger-500'}`}></div>
          <span className="text-xs text-dark-400">{isConnected ? 'Backend Connected' : 'Disconnected'}</span>
        </div>
      </div>

      <div className="flex-1 bg-dark-900 border border-dark-800 rounded-xl flex flex-col min-h-0 overflow-hidden">
        
        {/* Chat History */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.map((msg, idx) => (
            <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`flex max-w-[80%] ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                
                <div className={`flex-shrink-0 flex items-center justify-center w-8 h-8 rounded-full ${
                  msg.role === 'user' ? 'bg-primary-600 ml-3' : 'bg-accent-600 mr-3'
                }`}>
                  {msg.role === 'user' ? <User className="w-4 h-4 text-white" /> : <Bot className="w-4 h-4 text-white" />}
                </div>

                <div className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div className={`px-4 py-3 rounded-2xl ${
                    msg.role === 'user' 
                      ? 'bg-primary-600 text-white rounded-tr-none' 
                      : msg.error
                        ? 'bg-danger-900/50 border border-danger-800 text-danger-200 rounded-tl-none'
                        : 'bg-dark-800 border border-dark-700 text-dark-100 rounded-tl-none'
                  }`}>
                    {msg.role === 'user' ? (
                      <p className="whitespace-pre-wrap">{msg.content}</p>
                    ) : (
                      <div className="prose prose-invert max-w-none text-sm">
                        {renderMarkdown(msg.content)}
                      </div>
                    )}
                  </div>
                  <span className="text-[10px] text-dark-500 mt-1 px-1">
                    {format(msg.timestamp, 'HH:mm')}
                  </span>
                </div>

              </div>
            </div>
          ))}
          
          {loading && (
            <div className="flex justify-start">
              <div className="flex flex-row">
                <div className="flex-shrink-0 flex items-center justify-center w-8 h-8 rounded-full bg-accent-600 mr-3">
                  <Bot className="w-4 h-4 text-white" />
                </div>
                <div className="bg-dark-800 border border-dark-700 rounded-2xl rounded-tl-none px-4 py-3 flex items-center space-x-1">
                  <div className="w-2 h-2 bg-dark-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-dark-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                  <div className="w-2 h-2 bg-dark-400 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 bg-dark-950 border-t border-dark-800">
          <form onSubmit={handleSubmit} className="relative flex items-center">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask NetGuard AI about alerts, IPs, or network health..."
              className="w-full bg-dark-900 border border-dark-700 text-white rounded-full pl-6 pr-14 py-3 focus:outline-none focus:ring-1 focus:ring-primary-500 transition-all"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={!input.trim() || loading}
              className="absolute right-2 p-2 bg-primary-600 hover:bg-primary-500 disabled:bg-dark-700 disabled:text-dark-500 text-white rounded-full transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="flex justify-center mt-2">
            <p className="text-[10px] text-dark-500 flex items-center">
              <AlertCircle className="w-3 h-3 mr-1" />
              AI responses may contain inaccuracies. Verify critical security actions.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
