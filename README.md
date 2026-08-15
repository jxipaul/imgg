# AES Image Encryption Visualizer — ECB Penguin Flaw Demo

An interactive, client-side cryptography visualizer that visually demonstrates why **cipher mode** matters as much as algorithm selection. 

By encrypting the same image using two different modes of AES (Advanced Encryption Standard)—**AES-ECB (Electronic Codebook)** and **AES-GCM (Galois/Counter Mode)**—this web application illustrates the classic "ECB Penguin" security flaw: naive block-by-block encryption leaks visual structure, while secure stream/counter modes turn images into pure statistical noise.

---

## 🎯 Key Concepts & Purpose

- **Electronic Codebook (ECB) Mode (Weak)**: Encrypts each 16-byte block of plaintext independently with the same key. Identical pixel blocks (e.g., solid background areas) always encrypt to identical ciphertext blocks, preserving image outlines and silhouettes.
- **Galois/Counter Mode (GCM) (Strong)**: Combines counter-mode encryption with a unique 96-bit Initialization Vector (IV) and a 16-byte Galois authentication tag. Identical pixel blocks produce completely different ciphertext bytes, hiding all spatial patterns.
- **Bit-Exact Decryption**: Demonstrates that both ECB and GCM are technically working ciphers capable of 100% lossless image recovery, but only GCM provides true confidentiality.

---

## 🛠️ Tech Stack

| Layer | Technology | Usage |
| :--- | :--- | :--- |
| **Frontend UI** | HTML5, Vanilla CSS3 | Modern dark mode design system, glassmorphism, responsive grid, and custom typography (*Outfit*, *Inter*, *Fira Code*). |
| **Image Processing** | HTML5 `<canvas>` API | Extracting raw RGBA pixel arrays via `getImageData()` and rendering ciphertext/decrypted images via `putImageData()`. |
| **Secure Crypto** | **Web Crypto API** (`crypto.subtle`) | Built-in browser crypto engine for native **AES-GCM** encryption and decryption. |
| **Manual ECB Crypto** | **Custom Pure JS AES-128 Engine** | Zero-dependency implementation of AES-128 (`aes-ecb.js`) to manually perform block-by-block ECB encryption without block chaining. |
| **Backend** | *None (100% Client-Side)* | Operates entirely in the browser with zero external dependencies or server requirements. |

---

## ✨ Features

1. **Three-Panel Visualizer Grid**:
   - **Original Image**: Displays plaintext RGBA data and image dimensions.
   - **Encrypted (AES-ECB)**: Highlights pattern leakage and preserved silhouettes.
   - **Encrypted (AES-GCM)**: Displays pure statistical noise.

2. **Preset Sample Generators & Custom Upload**:
   - Includes bundled high-contrast flat-color logos (**"ECB Penguin"**, **"Shield & Key"**, **"Target Logo"**) optimal for demonstrating pattern leaks.
   - Drag-and-drop file uploader for testing custom user images.

3. **Decryption Verification**:
   - Reverses both ECB and GCM ciphertexts in real time.
   - Performs element-by-element byte array comparison, verifying **100% Bit-Exact Match (0 byte mismatch)**.

4. **Interactive Pixel & Block Inspector**:
   - Hover over any canvas pixel to view exact `(X, Y)` coordinates, block index, original RGBA hex values, and corresponding ciphertext bytes.

5. **Cryptographic Math Explainer**:
   - Educational drawer breaking down the mathematical difference between \(C_i = E_K(P_i)\) (ECB) and \(C_i = P_i \oplus E_K(\text{IV} \parallel i)\) (GCM).

---

## 📂 Project Structure

```
├── index.html                        # Main single-page web app markup
├── style.css                         # Dark theme design system & visualizer styling
├── aes-ecb.js                        # Pure JS AES-128 block cipher implementation
├── app.js                            # Web Crypto API integration, canvas handling, & UI logic
├── README.md                         # Project documentation
└── image_encryption_visualizer_plan.md  # Original implementation plan specification
```

---

## 🚀 How to Run Locally

Since the application is 100% client-side, you can run it using any static web server:

### Option 1: Python HTTP Server
```bash
python3 -m http.server 8080
```
Then open `http://localhost:8080` in your web browser.

### Option 2: Direct File Open
Simply double-click `index.html` or open it directly in Google Chrome, Firefox, or Safari.

---

## 🔬 How to Test the Demo

1. Select the **"ECB Penguin"** sample preset.
2. Click **"Encrypt Image"**. Observe how the Tux penguin outline is completely preserved in the AES-ECB panel, while AES-GCM turns into static.
3. Hover over the penguin's belly or eyes to inspect raw byte blocks in the **Interactive Pixel Inspector**.
4. Click **"Decrypt & Verify"** to confirm both ciphertexts recover the original image losslessly.
