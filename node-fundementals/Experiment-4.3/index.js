const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory seat state
const seats = Array.from({ length: 10 }, (_, i) => ({
  id: i + 1,
  status: 'available', // available | locked | booked
  lockedBy: null,
  lockExpires: null
}));

// Helper to clear expired locks
function clearExpiredLocks() {
  const now = Date.now();
  seats.forEach(seat => {
    if (seat.status === 'locked' && seat.lockExpires && seat.lockExpires < now) {
      seat.status = 'available';
      seat.lockedBy = null;
      seat.lockExpires = null;
    }
  });
}

// View available seats (output matches screenshot)
app.get('/seats', (req, res) => {
  clearExpiredLocks();
  const result = {};
  seats.forEach(seat => {
    result[seat.id] = { status: seat.status };
  });
  res.json(result);
});

// Lock a seat (output matches screenshot)
app.post('/lock/:id', (req, res) => {
  clearExpiredLocks();
  const seat = seats.find(s => s.id === Number(req.params.id));
  const user = req.body.user;
  if (!seat) return res.status(404).json({ message: 'Seat not found.' });
  if (!user) return res.status(400).json({ message: 'User is required.' });
  if (seat.status === 'booked') return res.status(400).json({ message: 'Seat already booked.' });
  if (seat.status === 'locked') return res.status(400).json({ message: 'Seat is currently locked.' });
  seat.status = 'locked';
  seat.lockedBy = user;
  seat.lockExpires = Date.now() + 60 * 1000; // 1 minute lock
  res.json({ message: `Seat ${seat.id} locked successfully. Confirm within 1 minute.` });
});

// Confirm booking (output matches screenshot)
app.post('/confirm/:id', (req, res) => {
  clearExpiredLocks();
  const seat = seats.find(s => s.id === Number(req.params.id));
  const user = req.body.user;
  if (!seat) return res.status(404).json({ message: 'Seat not found.' });
  if (!user) return res.status(400).json({ message: 'User is required.' });
  if (seat.status !== 'locked' || seat.lockedBy !== user) {
    return res.status(400).json({ message: 'Seat is not locked and cannot be booked' });
  }
  seat.status = 'booked';
  seat.lockedBy = user;
  seat.lockExpires = null;
  res.json({ message: `Seat ${seat.id} booked successfully!` });
});

app.listen(PORT, () => {
  console.log(`Ticket booking server running at http://localhost:${PORT}/`);
});
