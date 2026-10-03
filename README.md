# AES Cryptanalysis Workbench — ECB Pattern Leakage & GCM Authenticated Diffusion

An interactive, browser-native cryptanalysis workbench designed to visually demonstrate why **cipher mode** is as critical to data confidentiality as algorithm strength. By encrypting identical bitmap buffers using **AES-128-ECB (Electronic Codebook)** and **AES-128-GCM (Galois/Counter Mode)**, this tool contrasts naive deterministic block mapping against authenticated pseudo-random diffusion, demonstrates the classic "ECB Penguin" structural leakage, and verifies bit-perfect lossless recovery through inverse decryption.

---

## 🔬 Core Cryptographic Problem Statement

Traditional cryptography education relies heavily on hexadecimal strings and byte-stream output, making it difficult for learners to grasp why selecting a standard algorithm like AES (Advanced Encryption Standard) is insufficient if paired with an improper operational mode.

In raster images:
1. **Electronic Codebook (ECB) Mode (Weak / Insecure)**:
   $$\text{Encryption: } C_i = E_K(P_i) \qquad \text{Decryption: } P_i = D_K(C_i)$$
   Each 16-byte block of plaintext $P_i$ (corresponding to 4 RGBA pixels) is encrypted independently under key $K$. When the source image contains contiguous regions of uniform color (e.g., solid backgrounds, logos, or silhouettes), identical plaintext blocks deterministically yield identical ciphertext blocks ($P_a = P_b \implies C_a = C_b$). The visual structure, contours, and silhouettes remain completely exposed in the ciphertext.

2. **Galois/Counter Mode (GCM) (Strong / Authenticated)**:
   $$\text{Keystream: } S_i = E_K(\text{IV} \parallel i) \qquad \text{Ciphertext: } C_i = P_i \oplus S_i$$
   $$\text{Auth Tag: } T = \text{GHASH}_H(A, C, L) \oplus E_K(\text{IV} \parallel 0)$$
   Combines counter-mode stream encryption with a unique 96-bit Initialization Vector (IV) and a 128-bit Galois authentication tag. Because the block counter $i$ increments for every single 16-byte block, identical plaintext blocks are XORed with distinct keystream bytes. This guarantees true pseudo-random diffusion, transforming the raster into statistical noise ($H \approx 8.0$ bits/byte) while cryptographically authenticating data integrity.

---

## 🛠️ System Architecture & Technology Stack

| Layer | Component | Technical Role |
| :--- | :--- | :--- |
| **Workbench UI** | HTML5, Modern Responsive CSS3 | Dark workstation aesthetic, high-density telemetry panels, segmented toolbars, precision monospace data readouts (`Outfit`, `Inter`, `Fira Code`). |
| **Raster Engine** | HTML5 `<canvas>` API | Pixel buffer extraction via `getImageData()`, direct 32-bit/8-bit buffer manipulation, and overlay reticle rendering. |
| **ECB Cipher Engine** | Pure JavaScript AES-128 (`aes-ecb.js`) | Zero-dependency implementation of AES-128 core rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey and inverse operations) for independent block execution without chaining. |
| **GCM Cipher Engine** | W3C **Web Crypto API** (`crypto.subtle`) | Hardware-accelerated native AES-GCM encryption/decryption with 96-bit random IVs and 128-bit GHASH authentication tags. |
| **Integrity Proofs** | `crypto.subtle.digest("SHA-256")` | Hardware-accelerated computation of 256-bit cryptographic hashes for bit-exact verification between plaintext and decrypted states. |
| **Backend** | *None (100% Client-Side)* | All cryptographic operations, memory buffers, and canvas operations execute entirely in-browser with zero external network dependencies. |

---

## ✨ Key Features & Analytical Tooling

### 1. Tri-Panel Cryptanalysis Viewport
- **Panel 1: Source Plaintext Buffer (RGBA)**: Unmodified raster buffer displaying raw pixel dimensions, Shannon entropy, and block redundancy statistics.
- **Panel 2: AES-128-ECB (Weak Mode)**: Demonstrates severe deterministic pattern leakage, repeating block tiles, and preserved image contours.
- **Panel 3: AES-128-GCM (Authenticated Secure Mode)**: Demonstrates full pseudo-random diffusion and complete structural obfuscation.

### 2. Five High-Contrast Sample Presets & Custom Ingestion
- **🐧 Tux Penguin**: The classic Linux penguin on pure white background — maximum ECB pattern leak demonstration.
- **🛡️ Cyber Shield**: High-contrast layered security emblem with central keyhole.
- **🎯 Target Reticle**: Concentric geometric rings and fine crosshairs.
- **🏁 QR Matrix**: 2D data barcode demonstrating structural alignment pattern leaks.
- **🩻 Medical PACS**: Chest radiograph silhouette demonstrating real-world PACS DICOM medical imagery confidentiality risks.
- **📁 File Upload, Drag-and-Drop & Clipboard Paste (`Ctrl+V`)**: Test any custom image (auto-normalized to row-aligned 16-byte boundaries).

### 3. Interactive 16-Byte Block Inspector & Pattern Leak Analyzer
- **Synchronized Reticle**: Moving cursor over any viewport projects a synchronized crosshair and 16-byte (4-pixel) bounding box across all panels simultaneously.
- **Hex & ASCII Dump**: Real-time display of the active block's 16-byte plaintext, ECB ciphertext, and GCM ciphertext.
- **Repeating Block Highlighting**: Clicking any block scans the entire image and highlights all identical blocks across Plaintext and ECB panels. Shows exact match count and proves **100% deterministic correlation** in ECB vs **0% correlation** in GCM.
- **Cursor Lock/Unlock**: Click any block to lock telemetry for inspection; click unlock or press `Esc` to resume live tracking.

### 4. Information Theory & Shannon Entropy Telemetry
- **Shannon Entropy Metric**: Live computation of:
  $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
  Comparing low/structured source entropy, depressed ECB entropy, and near-ideal GCM entropy ($\approx 7.999$ bits/byte).
- **256-Bin Byte Frequency Spectrum**: Real-time canvas histogram charting byte frequency distributions (0x00 to 0xFF) — visually contrasting discrete ECB spikes against the flat horizontal band of GCM.
- **Block Statistics**: Total 16-byte blocks, unique plaintext blocks, unique ECB blocks (1:1 leakage match), and spatial redundancy percentage.

### 5. Lossless Decryption & Bit-Exact Verification Console
- **Cryptographic Hashes (SHA-256)**: Live 64-character hex digests of Source, Decrypted ECB, and Decrypted GCM buffers with real-time `MATCH (100%)` verification badges.
- **Byte-by-Byte Differential**: Element-by-element buffer comparison confirming **0 byte mismatch** ($0.000\%$).
- **Peak Signal-to-Noise Ratio (PSNR)**: Mathematical confirmation of $+\infty\text{ dB}$ (bit-perfect lossless reconstruction).
- **Difference Map Canvas**: Visual differential rendering ($|P_i - D_i|$) displaying pure black for identical reconstruction.
- **Execution Benchmarks**: Live timing (ms) and throughput calculations (MB/s).

### 6. Audit Logging & Export Capabilities
- **Export Audit Log (JSON)**: Generates a complete cryptographic audit report including image parameters, 128-bit key, 96-bit IV, entropy metrics, block statistics, SHA-256 digests, benchmarks, and formal findings.
- **PNG Download**: Export Plaintext, ECB Ciphertext, and GCM Ciphertext canvases directly to local storage.

### 7. Keyboard Shortcuts
- `Ctrl+E` / `Cmd+E`: Encrypt all modes
- `Ctrl+D` / `Cmd+D`: Decrypt & execute verification
- `Esc`: Reset / Unlock inspector
- `1` through `5`: Quick switch between presets (Penguin, Shield, Target, QR, Medical)

### 8. 📁 Universal File Vault (Encrypt & Decrypt Any File Format)
- **Universal Format Support**: Encrypt and decrypt any file format (`.pdf`, `.docx`, `.zip`, `.png`, `.jpg`, `.mp4`, `.mp3`, `.txt`, `.csv`, binary data, archives) with 100% client-side execution and zero server dependencies.
- **Autonomous `AESENC v1` Container**: Encrypted files are exported as self-describing `.enc` packages preserving the original file name, MIME type, cipher mode, 96-bit IV, 128-bit GHASH authentication tag, and reference SHA-256 digest.
- **Round-Trip Decryption & Bit-Exact Verification**: Re-import any `.enc` package to decrypt, automatically authenticate against the 128-bit GHASH tag (detecting any tampering or incorrect key), and verify 100% bit-exact SHA-256 restoration with 0 byte mismatch.
- **Integrated Live Content Preview**: Direct in-browser preview of recovered images, text documents, code, audio, and video files upon decryption.
- **1-Click Test Dossier**: Built-in sample confidential dossier generator for immediate zero-friction round-trip testing.

---

## 📂 Project Structure

```
├── index.html                        # Application workbench layout & semantic DOM
├── style.css                         # Dark workstation design system, HUD overlays & meters
├── aes-ecb.js                        # Pure JS AES-128 block cipher (SubBytes, MixColumns, ShiftRows)
├── app.js                            # Web Crypto API integration, canvas pipeline, entropy, & telemetry
└── README.md                         # Project & technical documentation
```

---

## 🚀 How to Run Locally

Because the workbench is 100% client-side with zero external dependencies, you can run it using any static server or open it directly:

### Option 1: Python HTTP Server (Recommended)
```bash
python3 -m http.server 8080
```
Then navigate to `http://localhost:8080` in your web browser (Google Chrome, Firefox, Safari, or Edge).

### Option 2: Node.js `npx serve`
```bash
npx serve .
```

### Option 3: Direct File Open
Simply double-click `index.html` or open it directly from your file manager.

---

## 🔍 Verification & Demonstration Walkthrough

Follow these steps to demonstrate the tool:

1. **Preset Selection**: Select the **"Tux Penguin"** preset from the topbar (or press `1`). Notice the source image metrics: 10,000 blocks (16-byte), low Shannon entropy (~1.34 bits/byte), and ~92.4% spatial redundancy.
2. **Execute Encryption**: Click **"ENCRYPT MODES"** (or press `Ctrl+E`).
   - Observe **Panel 2 (AES-128-ECB)**: The entire Tux Penguin silhouette, belly, beak, and eyes remain clearly visible through the encrypted pixels.
   - Observe **Panel 3 (AES-128-GCM)**: The image is transformed into pure statistical static with zero structural patterns.
3. **Inspect Entropy Spectrum**: Examine the **Shannon Entropy & Byte Frequency Spectrum** dock.
   - Note the discrete yellow spikes in ECB mode vs the flat emerald uniform distribution in GCM mode.
   - Observe GCM entropy reaching ~8.00 bits/byte (theoretical maximum).
4. **Interactive Block Analysis**:
   - Hover the reticle over the penguin's white belly or background.
   - Observe that the active 16-byte block repeats across thousands of positions.
   - Look at the **Interactive 16-Byte Block Inspector**: Every single repeating plaintext block maps to the *exact same 16-byte ciphertext block* in ECB (100% correlation), while mapping to completely different bytes in GCM (0% correlation).
5. **Decryption & Bit-Exact Verification**:
   - Click **"DECRYPT & VERIFY"** (or press `Ctrl+D`).
   - Review the **SHA-256 Digest Matrix**: Confirm that the SHA-256 hashes of Plaintext, Decrypted ECB, and Decrypted GCM are identical bit-for-bit.
   - Verify the Differential Map is pure black with 0 byte mismatches and $+\infty\text{ dB}$ PSNR.
   - Both ECB and GCM are mathematically valid ciphers, but ECB's lack of IV and counter chaining destroys confidentiality for structured data.
6. **Specifications Modal**: Click **"Cipher Specs"** in the topbar to review the formal mathematical formulations and verification checklist.
7. **Export Audit**: Click **"Export Audit"** to generate a JSON report containing full cryptographic benchmarks and SHA-256 verification proofs.

---

## 📜 License

MIT License

