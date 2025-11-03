import { useState } from "react";
import AddBookForm from "./AddBookForm";
import BookList from "./BookList";
import SearchBar from "./SearchBar";

function LibraryManagement() {
  const [books, setBooks] = useState([
    { title: "1984", author: "George Orwell" },
    { title: "The Great Gatsby", author: "F. Scott Fitzgerald" },
    { title: "To Kill a Mockingbird", author: "Harper Lee" },
  ]);

  const [searchTerm, setSearchTerm] = useState("");

  const addBook = (title, author) => {
    if (title.trim() && author.trim()) {
      setBooks([...books, { title, author }]);
    }
  };

  const removeBook = (index) => {
    setBooks(books.filter((_, i) => i !== index));
  };

  const filteredBooks = books.filter(
    (book) =>
      book.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      book.author.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ border: "1px solid black", padding: "15px", margin: "10px" }}>
      <h2>Library Management</h2>
      <SearchBar searchTerm={searchTerm} setSearchTerm={setSearchTerm} />
      <AddBookForm addBook={addBook} />
      <BookList books={filteredBooks} removeBook={removeBook} />
    </div>
  );
}

export default LibraryManagement;
