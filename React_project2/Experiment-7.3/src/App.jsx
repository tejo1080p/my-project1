import Student from "./classes/Student.js";
impreort Teacher from "./classes/Teacher.js";

function App() {
  const student1 = new Student("Alice", 20, "Computer Science");
  const teacher1 = new Teacher("Mr. Smith", 40, "Mathematics");

  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h2>Inheritance Demo</h2>
      <p>{student1.displayInfo()}</p>
      <p>{teacher1.displayInfo()}</p>
    </div>
  );
}

export default App;