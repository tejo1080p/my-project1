import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import ProductCard from 'C:\Users\gudal\OneDrive\Desktop\fullstack\react_project\experiment-3.1\src\component\ProductCard.jsx'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
      <h1>Tejo</h1>
      <ProductCard />
    </>
  )
}

export default App
