const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());

let cards = [
  { id: 1, suit: 'Hearts', value: 'Ace' },
  { id: 2, suit: 'Spades', value: 'King' },
  { id: 3, suit: 'Diamonds', value: 'Queen' },
  { "suit": "Clubs", "value": "Jack" }
];

// Home route
app.get('/', (req, res) => {
  res.send('Card API is running. Try /cards');
});

// List all cards
app.get('/cards', (req, res) => {
  res.json(cards);
});

// Get a card by ID
app.get('/cards/:id', (req, res) => {
  const card = cards.find(c => c.id === Number(req.params.id));
  if (card) {
    res.json(card);
  } else {
    res.status(404).json({ message: 'Card not found' });
  }
});

// Add a new card (robust against missing/invalid body)
app.post('/cards', (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ message: 'Request body must be JSON.' });
  }
  const { suit, value } = req.body;
  if (!suit || !value) {
    return res.status(400).json({ message: 'Suit and value are required.' });
  }
  const nextId = cards.length ? Math.max(...cards.map(c => c.id)) + 1 : 1;
  const newCard = { id: nextId, suit, value };
  cards.push(newCard);
  res.status(201).json(newCard);
});

// Delete a card by ID
app.delete('/cards/:id', (req, res) => {
  const index = cards.findIndex(c => c.id === Number(req.params.id));
  if (index !== -1) {
    const removed = cards.splice(index, 1)[0];
    res.json({ message: `Card with ID ${removed.id} removed`, card: removed });
  } else {
    res.status(404).json({ message: 'Card not found' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});
