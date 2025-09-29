import React, { useState } from 'react';
import MovieCards from './components/MovieCards.jsx';
import moviesData from './movies.js';

function App() {
  const [movies, setMovies] = useState(moviesData);

  const handleDelete = (title) => {
    setMovies(movies.filter(movie => movie.title !== title));
  };

  return (
    <div style={{ padding: '20px' }}>
      <h1>Movie Cards</h1>
      <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
        {movies.map(movie => (
          <MovieCards key={movie.title} movie={movie} onDelete={handleDelete} />
        ))}
      </div>
    </div>
  );
}

export default App;
