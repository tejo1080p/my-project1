const dropdown = document.getElementById("categoryFilter");
const products = document.querySelectorAll(".product");

dropdown.addEventListener("change", function () {
    const selectedCategory = this.value;

    products.forEach(product => {
        const productCategory = product.getAttribute("data-category");

        if (selectedCategory === "All" || productCategory === selectedCategory) {
            product.style.display = "block";
        } else {
            product.style.display = "none";
        }
    });
});
