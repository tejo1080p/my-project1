import "./App.css"; // make sure styles are applied
import LibraryManagement from "./component/LibraryManagement";

function App() {
  return (
    <div style={{ backgroundColor: "white", minHeight: "100vh", padding: "20px" }}>
      <LibraryManagement />
    </div>
  );
}

export default App;
