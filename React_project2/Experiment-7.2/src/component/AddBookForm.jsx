import { useState } from "react";

function AddBookForm({ addBook }) {
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState("");

  const handleSubmit = () => {
    addBook(title, author);
    setTitle("");
    setAuthor("");
  };

  return (
    <div>
      <input
        type="text"
        placeholder="New book title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        style={{ marginRight: "5px" }}
      />
      <input
        type="text"
        placeholder="New book author"
        value={author}
        onChange={(e) => setAuthor(e.target.value)}
        style={{ marginRight: "5px" }}
      />
      <button onClick={handleSubmit}>Add Book</button>
    </div>
  );
}

export default AddBookForm;
