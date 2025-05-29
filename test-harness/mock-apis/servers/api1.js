const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8081;

app.use(cors());
app.use(express.json());

// Simulate user management API
let users = [
  { id: 1, name: 'Alice', email: 'alice@example.com', active: true },
  { id: 2, name: 'Bob', email: 'bob@example.com', active: false },
  { id: 3, name: 'Charlie', email: 'charlie@example.com', active: true }
];

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'user-api', timestamp: new Date().toISOString() });
});

// Get all users
app.get('/api/users', (req, res) => {
  // Simulate processing delay
  setTimeout(() => {
    res.json({
      success: true,
      data: users,
      count: users.length,
      timestamp: new Date().toISOString()
    });
  }, Math.random() * 100);
});

// Get user by ID
app.get('/api/users/:id', (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (user) {
    res.json({ success: true, data: user });
  } else {
    res.status(404).json({ success: false, error: 'User not found' });
  }
});

// Create user
app.post('/api/users', (req, res) => {
  const newUser = {
    id: users.length + 1,
    name: req.body.name || 'Anonymous',
    email: req.body.email || 'unknown@example.com',
    active: req.body.active !== undefined ? req.body.active : true
  };
  users.push(newUser);
  res.status(201).json({ success: true, data: newUser });
});

// Update user
app.put('/api/users/:id', (req, res) => {
  const userIndex = users.findIndex(u => u.id === parseInt(req.params.id));
  if (userIndex !== -1) {
    users[userIndex] = { ...users[userIndex], ...req.body };
    res.json({ success: true, data: users[userIndex] });
  } else {
    res.status(404).json({ success: false, error: 'User not found' });
  }
});

// Delete user
app.delete('/api/users/:id', (req, res) => {
  const userIndex = users.findIndex(u => u.id === parseInt(req.params.id));
  if (userIndex !== -1) {
    const deletedUser = users.splice(userIndex, 1)[0];
    res.json({ success: true, data: deletedUser });
  } else {
    res.status(404).json({ success: false, error: 'User not found' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`User API listening on port ${PORT}`);
});