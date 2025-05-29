const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8083;

app.use(cors());
app.use(express.json());

// Simulate notification/messaging API with WebSocket-like behavior
let notifications = [];
let messageId = 1;

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'notification-api', timestamp: new Date().toISOString() });
});

// Get notifications
app.get('/api/notifications', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  
  const paginatedNotifications = notifications.slice(offset, offset + limit);
  
  res.json({
    success: true,
    data: paginatedNotifications,
    total: notifications.length,
    limit,
    offset,
    has_more: offset + limit < notifications.length
  });
});

// Send notification
app.post('/api/notifications', (req, res) => {
  const notification = {
    id: messageId++,
    type: req.body.type || 'info',
    title: req.body.title || 'Default Notification',
    message: req.body.message || 'This is a test notification',
    recipient: req.body.recipient || 'user@example.com',
    priority: req.body.priority || 'normal',
    created_at: new Date().toISOString(),
    status: 'sent',
    delivery_attempts: 1,
    metadata: {
      source: 'test-harness',
      channel: req.body.channel || 'email',
      tags: req.body.tags || ['test', 'automated']
    }
  };
  
  notifications.unshift(notification); // Add to beginning
  
  // Keep only last 100 notifications
  if (notifications.length > 100) {
    notifications = notifications.slice(0, 100);
  }
  
  res.status(201).json({ success: true, notification });
});

// Real-time events endpoint (Server-Sent Events simulation)
app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  
  // Send initial event
  res.write(`data: ${JSON.stringify({
    type: 'connected',
    timestamp: new Date().toISOString(),
    client_id: Math.random().toString(36).substring(2, 15)
  })}\n\n`);
  
  // Send periodic events
  const interval = setInterval(() => {
    const event = {
      type: 'heartbeat',
      timestamp: new Date().toISOString(),
      active_connections: Math.floor(Math.random() * 100) + 10,
      system_load: Math.random().toFixed(2),
      memory_usage: Math.floor(Math.random() * 80) + 20
    };
    
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  }, 5000);
  
  // Clean up on client disconnect
  req.on('close', () => {
    clearInterval(interval);
  });
});

// Bulk operations endpoint (larger payloads)
app.post('/api/bulk', (req, res) => {
  const operations = req.body.operations || [];
  const results = operations.map((op, index) => ({
    operation_id: index + 1,
    type: op.type || 'unknown',
    status: Math.random() > 0.1 ? 'success' : 'failed',
    processing_time_ms: Math.floor(Math.random() * 1000) + 50,
    data: op.data || {},
    timestamp: new Date().toISOString()
  }));
  
  // Simulate processing delay for bulk operations
  setTimeout(() => {
    res.json({
      success: true,
      batch_id: Date.now(),
      total_operations: operations.length,
      successful: results.filter(r => r.status === 'success').length,
      failed: results.filter(r => r.status === 'failed').length,
      results,
      processing_time_ms: Math.floor(Math.random() * 2000) + 500
    });
  }, Math.random() * 1000 + 500);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Notification API listening on port ${PORT}`);
});