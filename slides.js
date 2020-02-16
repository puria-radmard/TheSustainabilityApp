let slideIndex = 0;
showSlides(slideIndex);
let timeoutHandle;

// Next/previous controls
function plusSlides(n) {
    window.clearTimeout(timeoutHandle);
    showSlides(slideIndex += n);
    timeoutHandle = window.setInterval(() => {
        slideIndex++;
        showSlides(slideIndex);
    }, 4000);
}

// Thumbnail image controls
function currentSlide(n) {
    window.clearTimeout(timeoutHandle);
    showSlides(slideIndex = n);
    timeoutHandle = window.setInterval(() => {
        slideIndex++;
        showSlides(slideIndex);
    }, 4000);
}

async function showSlides(n) {
    let i;
    const slides = document.getElementsByClassName("mySlides");
    const dots = document.getElementsByClassName("dot");
    if (n > slides.length) {slideIndex = 1}
    if (n < 1) {slideIndex = slides.length}
    for (i = 0; i < slides.length; i++) {
        slides[i].style.display = "none";
    }
    for (i = 0; i < dots.length; i++) {
        dots[i].className = dots[i].className.replace(" active", "");
    }
    slides[slideIndex-1].style.display = "block";
    dots[slideIndex-1].className += " active";
}

timeoutHandle = window.setInterval(() => {
    slideIndex++;
    showSlides(slideIndex);
}, 4000);