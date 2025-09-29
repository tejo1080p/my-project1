import React from 'react';

function MovieCards({ movie, onDelete }) {
  return (
    <div style={{
      border: '1px solid #ccc',
      padding: '10px',
      borderRadius: '8px',
      width: '200px'
    }}>
      <h2>{movie.title}</h2>
      <p>Genre: {movie.genre}</p>
      <p>Rating: {movie.rating}</p>
      <button onClick={() => onDelete(movie.title)}>Delete</button>
    </div>
  );
}

export default MovieCards;
