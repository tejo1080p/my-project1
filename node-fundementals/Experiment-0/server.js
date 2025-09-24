const http = require('http');

const handler = (req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ data: 'Hello, World!\n' }));
};

// Try to listen starting at base port and increment on EADDRINUSE
function startServer(port, maxPort = port + 10) {
  const server = http.createServer(handler);

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`Port ${port} in use, trying ${port + 1}...`);
      if (port + 1 > maxPort) {
        console.error('No free ports found in range, exiting.');
        process.exit(1);
      }
      // try next port
      setTimeout(() => startServer(port + 1, maxPort), 200);
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });

  server.listen(port, () => {
    console.log(`✅ Server running at http://localhost:${port}/`);
  });
}

const BASE_PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
startServer(BASE_PORT);
