
function BookItem({ book, index, removeBook }) {
  return (
    <div
      style={{
        border: "1px solid #ccc",
        padding: "8px",
        marginBottom: "5px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
      }}
    >
      <span>
        <strong>{book.title}</strong> by {book.author}
      </span>
      <button onClick={() => removeBook(index)}>Remove</button>
    </div>
  );
}

export default BookItem;
