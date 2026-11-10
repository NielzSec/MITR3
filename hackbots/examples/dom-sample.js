// Amostra sintética de DOM-XSS de laboratório (MITR3)
const params = new URLSearchParams(window.location.search);
const query = params.get("search");
if (query) {
    document.getElementById("output").innerHTML = "Resultado para: " + query;
}
