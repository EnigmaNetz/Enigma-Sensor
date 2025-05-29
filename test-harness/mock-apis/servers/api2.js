const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8082;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.raw({ limit: '50mb', type: 'application/octet-stream' }));

// Simulate data analytics API with large payloads
let analytics = {
  sessions: 15420,
  pageviews: 89302,
  unique_visitors: 12453,
  bounce_rate: 0.34,
  avg_session_duration: 245,
  top_pages: [
    { path: '/dashboard', views: 15420, avg_time: 142 },
    { path: '/reports', views: 8930, avg_time: 287 },
    { path: '/settings', views: 5621, avg_time: 93 },
    { path: '/profile', views: 3456, avg_time: 156 }
  ],
  hourly_data: Array.from({ length: 24 }, (_, i) => ({
    hour: i,
    visits: Math.floor(Math.random() * 1000) + 100,
    conversions: Math.floor(Math.random() * 50) + 5
  }))
};

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'analytics-api', timestamp: new Date().toISOString() });
});

// Get analytics overview
app.get('/api/analytics', (req, res) => {
  // Simulate heavy processing
  setTimeout(() => {
    res.json({
      success: true,
      data: analytics,
      generated_at: new Date().toISOString(),
      processing_time_ms: Math.floor(Math.random() * 500) + 100
    });
  }, Math.random() * 300 + 200);
});

// Post data (simulate receiving analytics events)
app.post('/api/data', (req, res) => {
  const event = {
    id: Date.now(),
    type: req.body.type || 'pageview',
    data: req.body.data || {},
    timestamp: new Date().toISOString(),
    processed: true
  };
  
  // Simulate processing delay
  setTimeout(() => {
    res.json({ success: true, event });
  }, Math.random() * 50);
});

// Simulate file upload endpoint (generates larger response)
app.post('/api/upload', (req, res) => {
  const fileData = {
    id: Date.now(),
    filename: req.body.filename || 'unknown.txt',
    size: Math.floor(Math.random() * 10000000) + 1000,
    checksum: Math.random().toString(36).substring(2, 15),
    chunks: Math.floor(Math.random() * 100) + 1,
    status: 'processing',
    metadata: {
      uploaded_at: new Date().toISOString(),
      content_type: req.body.content_type || 'application/octet-stream',
      processing_queue_position: Math.floor(Math.random() * 50) + 1
    }
  };
  
  res.json({ success: true, file: fileData });
});

// Delete temporary data
app.delete('/api/temp/:id', (req, res) => {
  res.json({ 
    success: true, 
    deleted_id: req.params.id,
    timestamp: new Date().toISOString() 
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Analytics API listening on port ${PORT}`);
});