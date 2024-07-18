document.addEventListener("DOMContentLoaded", () => {
  const animations = new Set();
  const emoteImages = document.querySelectorAll("#example .emote");
  const totalImages = emoteImages.length;
  let imagesLoaded = 0;

  console.log(`Total emote images found: ${totalImages}`);

  function setupAnimation(img) {
    img.style.visibility = "hidden";

    const onImageLoaded = () => {
      img.decode().then(() => {
        animations.add(img);
        imagesLoaded++;
        console.log(
          `Image loaded and decoded: ${img.src} (${imagesLoaded}/${totalImages})`
        );
        img.style.visibility = "visible";

        // When all images are loaded, synchronize animations
        if (imagesLoaded === totalImages) {
          console.log("All images loaded. Synchronizing animations.");
          synchronizeAnimations();
        }
      });
    };

    // Add load event listener
    img.addEventListener("load", onImageLoaded);

    // If the image is already cached and loaded, fire the load handler manually
    if (img.complete) {
      onImageLoaded();
      img.removeEventListener("load", onImageLoaded); // Remove the listener to prevent double calling
    }
  }

  function synchronizeAnimations() {
    animations.forEach((img) => {
      const src = img.src;
      img.src = ""; // Force reload
      img.src = src;
      console.log(`Image reloaded: ${img.src}`);
    });
  }

  const exampleContainer = document.getElementById("example");
  if (exampleContainer) {
    emoteImages.forEach((img) => {
      setupAnimation(img);
    });
  } else {
    console.error('Element with id "example" not found.');
  }
});