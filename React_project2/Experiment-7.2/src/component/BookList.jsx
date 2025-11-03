import BookItem from "./BookItem";

function BookList({ books, removeBook }) {
  return (
    <div style={{ marginTop: "15px" }}>
      {books.map((book, index) => (
        <BookItem
          key={index}
          book={book}
          index={index}
          removeBook={removeBook}
        />
      ))}
    </div>
  );
}

export default BookList;
