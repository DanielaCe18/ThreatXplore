//JAVASCRIPT for Toggle Menu
var navLinks = document.getElementById("navLinks");

function showMenu() {
    navLinks.style.right = "0";
}

function hideMenu() {
    navLinks.style.right = "-200px";
}

/**
 * const first_text = document.querySelector(".first-text");
 * const testLoad = () => {
    setTimeout(() => {
        first_text.textContent = "Less";
    }, timeout);

    setTimeout(() => {
        first_text.textContent = "More;
    }, timeout);
}
 * 
 */


/**LEARN MORE PAGE */
let nextBtn = document.querySelector('.next');
let prevBtn = document.querySelector('.prev');

let slider = document.querySelector('.learnMore');
let sliderList = slider.querySelector('.learnMore .list');
let thumbnail = document.querySelector('.thumbnail');
let thumbnailItems = thumbnail.querySelectorAll('.item');

thumbnail.appendChild(thumbnailItems[0]);

//Function for the next button
nextBtn.onclick = function () {
    moveSlider('next');
}

//Function for the prev button
prevBtn.onclick = function () {
    moveSlider('prev');
}

function moveSlider(direction) {
    let sliderItems = sliderList.querySelectorAll('.item');
    let thumbnailItems = document.querySelectorAll('.thumbnail .item');
    if (direction == 'next') {
        sliderList.appendChild(sliderItems[0]);
        thumbnail.appendChild(thumbnailItems[0]);
        slider.classList.add('next');
    } else{
        sliderList.prepend(sliderItems[sliderItems.length -1]);
        thumbnail.prepend(thumbnailItems[thumbnailItems.length - 1]);
        slider.classList.add('prev');
    }

    slider.addEventListener('animationend', function() {
        if (direction == 'next') {
            slider.classList.remove('next');
        } else {
            slider.classList.remove('prev');
        }
    }, {once: true}) //Remove the event Listener after it's triggered once
}