function ProductCard({ name, price, stock }) {
  return (
    <div className="product-card">
      <h3>{name}</h3>
      <p>Price: ${price}</p>
      <p>Status: {stock}</p>
    </div>
  );
}
export default ProductCard;