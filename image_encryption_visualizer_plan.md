# Implementation Plan — Image Encryption Visualizer

### Concept
Encrypt the same image two different ways — a weak/naive mode (AES-ECB) that leaks the image's visual structure through the ciphertext, and a strong mode (AES-GCM/CBC) that turns it into pure random noise. Shown side by side, this is the classic "ECB penguin" demonstration of why cipher *mode* matters, not just algorithm strength.

### Tech Stack
- Single-file React app
- Web Crypto API for AES-GCM/CBC (built-in, supports these natively)
- **For ECB**: Web Crypto API does NOT support ECB mode directly (deliberately, since it's insecure) — implement ECB manually: split the raw pixel bytes into 16-byte blocks and AES-encrypt each block independently using `crypto.subtle.encrypt` with AES-CTR/raw block trick, OR simpler: use a small pure-JS AES implementation for the ECB demo specifically (a minimal single-block AES encrypt function is enough, since ECB = "encrypt each block the same way independently")
- HTML5 `<canvas>` to read/write raw pixel data

### Core Flow
1. User uploads an image (or picks a provided sample — a simple flat-color-block image with a logo works best to show the leak clearly)
2. Draw image to a canvas, extract raw pixel bytes (`getImageData`)
3. **Path A (weak)**: encrypt pixel bytes in fixed 16-byte blocks independently (ECB-style) → write encrypted bytes back into a canvas as pixel data → render. Because identical blocks of pixels (like flat background areas) encrypt to identical output, the image's outline/structure is still visible in the "encrypted" version
4. **Path B (strong)**: encrypt the same pixel bytes with AES-GCM (or CBC with random IV) → the ciphertext bytes are statistically random → when rendered as pixels, it's pure static/noise, no structure visible
5. Display three images side by side: Original → "Encrypted (ECB — weak)" → "Encrypted (GCM — strong)"
6. Add a decrypt button to reverse both and confirm the original image is recoverable from each (proving both are technically "encryption", but only one is safe)

### UI Sections
1. **Upload/sample picker** — file input + a "use sample image" button (recommend bundling one flat-logo-style PNG so the leak is guaranteed visible)
2. **Three-panel image display** — Original / ECB output / GCM output, equal size, side by side
3. **Explainer captions under each panel** — e.g., under ECB: "Notice the outline is still visible — identical pixel blocks always encrypt the same way." Under GCM: "No visible structure — same key size, different mode."
4. **Decrypt button** — reverses both, shows both successfully return to the original (reinforcing "both are technically working ciphers — only the mode differs")

### Step-by-Step Build Order (for the coding agent)
1. Scaffold layout: upload control + three empty canvas placeholders + captions
2. Implement image load → draw to a source canvas → `getImageData()` to get raw RGBA byte array
3. Implement a minimal single-block AES-ECB encrypt (encrypt each independent 16-byte chunk of the pixel byte array using the same key, no chaining) — note: to visibly preserve structure, keep the RGBA byte layout intact per pixel row rather than fully randomizing block boundaries across the array
4. Implement AES-GCM encrypt using `crypto.subtle.encrypt` directly on the same byte array (need random IV, and note the output will have length overhead from the auth tag — truncate or pad to keep it renderable as pixels)
5. Write both resulting byte arrays back into two new canvases via `putImageData()`, sized identically to original
6. Render all three canvases side by side with captions
7. Implement decrypt: reverse ECB (decrypt each block back) and reverse GCM (standard decrypt) → `putImageData` back into two more canvases (or replace in place) → confirm both recover the original
8. Polish: pick or generate a sample image with large flat color areas + a simple logo/shape (this is what makes the ECB leak dramatic and visible — a busy/noisy photo won't show the effect well)

### Key Implementation Note (important for a solid demo)
The ECB leak effect ONLY shows up clearly if the sample image has large uniform-color regions (like the classic Linux "ECB Penguin" example). Test with a simple flat-logo PNG, not a photo — a photo already looks noisy so the leak won't be visually obvious. Bundle a suitable sample image rather than relying on user uploads.

### What NOT to build
- No real ECB library dependency — implement the minimal block-encrypt-independently logic directly, that's the entire point of the demo
- No huge image support — cap to small images (e.g., 200x200) so pixel-level encryption runs fast in-browser
- No mobile-camera capture flow — keep upload simple (file picker only)

### Problem framing (for report/slide)
Not all encryption is equally safe — the same algorithm (AES) can leak structure or hide it completely depending on the mode used. This project visually demonstrates the real, well-documented ECB-mode flaw by encrypting an image two ways and showing that "it looks encrypted" isn't the same as "it's actually secure."
