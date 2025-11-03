import './App.css'
import ProductCard from './component/ProductCard.jsx'

function App() {
  return (
    <>
      <h1 className="site-title">Sharath</h1>

      <div className="products-container">
        <h2 className="products-title">Products List</h2>
        <div id="product-list">
          <ProductCard name="Wireless Mouse" price={25.99} stock="In Stock" />
          <ProductCard name="Keyboard" price={45.5} stock="Out of Stock" />
          <ProductCard name="Monitor" price={199.99} stock="In Stock" />
        </div>
      </div>
    </>
  )
}

export default App