/**
 * Image Encryption Visualizer Application Logic
 * Integrates Web Crypto API (AES-GCM) and manual pure JS AES-128 (AES-ECB)
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const canvasOriginal = document.getElementById("canvas-original");
  const canvasEcb = document.getElementById("canvas-ecb");
  const canvasGcm = document.getElementById("canvas-gcm");
  const canvasDecEcb = document.getElementById("canvas-dec-ecb");
  const canvasDecGcm = document.getElementById("canvas-dec-gcm");

  const ctxOriginal = canvasOriginal.getContext("2d", { willReadFrequently: true });
  const ctxEcb = canvasEcb.getContext("2d");
  const ctxGcm = canvasGcm.getContext("2d");
  const ctxDecEcb = canvasDecEcb.getContext("2d");
  const ctxDecGcm = canvasDecGcm.getContext("2d");

  const inputKeyHex = document.getElementById("aes-key-hex");
  const btnGenKey = document.getElementById("btn-gen-key");
  const btnEncrypt = document.getElementById("btn-encrypt");
  const btnDecrypt = document.getElementById("btn-decrypt");
  const btnReset = document.getElementById("btn-reset");
  const imageUpload = document.getElementById("image-upload");

  const placeholderEcb = document.getElementById("placeholder-ecb");
  const placeholderGcm = document.getElementById("placeholder-gcm");
  const decryptionSection = document.getElementById("decryption-section");
  const statusBanner = document.getElementById("status-banner");
  const statusText = document.getElementById("status-text");

  // Inspector Elements
  const inspectCoords = document.getElementById("inspect-coords");
  const inspectOrigHex = document.getElementById("inspect-orig-hex");
  const inspectEcbHex = document.getElementById("inspect-ecb-hex");
  const inspectGcmHex = document.getElementById("inspect-gcm-hex");

  // Stats Elements
  const metaOriginal = document.getElementById("meta-original");
  const statOrigSize = document.getElementById("stat-orig-size");

  // State Variables
  let currentWidth = 200;
  let currentHeight = 200;
  let originalImageData = null; // Uint8ClampedArray (RGBA)
  let ecbCipherBytes = null;    // Uint8Array (RGBA encrypted)
  let gcmCipherBytes = null;    // Uint8Array (RGBA encrypted + auth tag)
  let currentGcmIv = null;      // 12-byte IV for GCM

  // --- 1. Helper Functions ---
  function hexToBytes(hex) {
    hex = hex.replace(/[^0-9a-fA-F]/g, "");
    if (hex.length < 32) {
      hex = hex.padEnd(32, "0");
    } else if (hex.length > 32) {
      hex = hex.substring(0, 32);
    }
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16) || 0;
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function updateStatus(message, type = "info") {
    statusText.innerHTML = message;
    statusBanner.className = `status-banner banner-${type}`;
  }

  // --- 2. Preset Sample Image Generators ---
  function loadPresetSample(type = "shield") {
    currentWidth = 200;
    currentHeight = 200;
    canvasOriginal.width = currentWidth;
    canvasOriginal.height = currentHeight;
    canvasEcb.width = currentWidth;
    canvasEcb.height = currentHeight;
    canvasGcm.width = currentWidth;
    canvasGcm.height = currentHeight;
    canvasDecEcb.width = currentWidth;
    canvasDecEcb.height = currentHeight;
    canvasDecGcm.width = currentWidth;
    canvasDecGcm.height = currentHeight;

    ctxOriginal.clearRect(0, 0, currentWidth, currentHeight);

    if (type === "shield") {
      // Flat navy background
      ctxOriginal.fillStyle = "#0a192f";
      ctxOriginal.fillRect(0, 0, currentWidth, currentHeight);

      // Large shield outline & flat fill
      ctxOriginal.fillStyle = "#00f5d4";
      ctxOriginal.beginPath();
      ctxOriginal.moveTo(100, 30);
      ctxOriginal.lineTo(160, 50);
      ctxOriginal.lineTo(160, 110);
      ctxOriginal.quadraticCurveTo(160, 165, 100, 180);
      ctxOriginal.quadraticCurveTo(40, 165, 40, 110);
      ctxOriginal.lineTo(40, 50);
      ctxOriginal.closePath();
      ctxOriginal.fill();

      // Inner shield detail
      ctxOriginal.fillStyle = "#00bbf9";
      ctxOriginal.beginPath();
      ctxOriginal.moveTo(100, 45);
      ctxOriginal.lineTo(145, 62);
      ctxOriginal.lineTo(145, 105);
      ctxOriginal.quadraticCurveTo(145, 150, 100, 165);
      ctxOriginal.quadraticCurveTo(55, 150, 55, 105);
      ctxOriginal.lineTo(55, 62);
      ctxOriginal.closePath();
      ctxOriginal.fill();

      // Keyhole shape in center
      ctxOriginal.fillStyle = "#0a192f";
      ctxOriginal.beginPath();
      ctxOriginal.arc(100, 95, 14, 0, Math.PI * 2);
      ctxOriginal.fill();
      ctxOriginal.beginPath();
      ctxOriginal.moveTo(92, 98);
      ctxOriginal.lineTo(108, 98);
      ctxOriginal.lineTo(112, 125);
      ctxOriginal.lineTo(88, 125);
      ctxOriginal.closePath();
      ctxOriginal.fill();

    } else if (type === "penguin") {
      // Classic Tux Penguin style flat-color silhouette
      // Pure white flat background (Ideal for ECB demonstration)
      ctxOriginal.fillStyle = "#ffffff";
      ctxOriginal.fillRect(0, 0, currentWidth, currentHeight);

      // Black body
      ctxOriginal.fillStyle = "#000000";
      ctxOriginal.beginPath();
      ctxOriginal.ellipse(100, 110, 55, 65, 0, 0, Math.PI * 2);
      ctxOriginal.fill();

      // Head
      ctxOriginal.beginPath();
      ctxOriginal.arc(100, 55, 38, 0, Math.PI * 2);
      ctxOriginal.fill();

      // White belly
      ctxOriginal.fillStyle = "#ffffff";
      ctxOriginal.beginPath();
      ctxOriginal.ellipse(100, 120, 34, 45, 0, 0, Math.PI * 2);
      ctxOriginal.fill();

      // Eyes
      ctxOriginal.beginPath();
      ctxOriginal.arc(88, 50, 8, 0, Math.PI * 2);
      ctxOriginal.arc(112, 50, 8, 0, Math.PI * 2);
      ctxOriginal.fill();

      ctxOriginal.fillStyle = "#000000";
      ctxOriginal.beginPath();
      ctxOriginal.arc(90, 50, 3, 0, Math.PI * 2);
      ctxOriginal.arc(110, 50, 3, 0, Math.PI * 2);
      ctxOriginal.fill();

      // Yellow beak
      ctxOriginal.fillStyle = "#ffb703";
      ctxOriginal.beginPath();
      ctxOriginal.moveTo(85, 62);
      ctxOriginal.lineTo(115, 62);
      ctxOriginal.lineTo(100, 78);
      ctxOriginal.closePath();
      ctxOriginal.fill();

      // Orange feet
      ctxOriginal.fillStyle = "#fb8500";
      ctxOriginal.beginPath();
      ctxOriginal.ellipse(75, 172, 22, 10, -0.2, 0, Math.PI * 2);
      ctxOriginal.ellipse(125, 172, 22, 10, 0.2, 0, Math.PI * 2);
      ctxOriginal.fill();

    } else if (type === "target") {
      // Flat high-contrast concentric target
      ctxOriginal.fillStyle = "#0f172a";
      ctxOriginal.fillRect(0, 0, currentWidth, currentHeight);

      const colors = ["#ff0054", "#ffffff", "#00bbf9", "#ffffff", "#ff9f1c"];
      const radii = [80, 60, 40, 20, 8];

      radii.forEach((r, idx) => {
        ctxOriginal.fillStyle = colors[idx];
        ctxOriginal.beginPath();
        ctxOriginal.arc(100, 100, r, 0, Math.PI * 2);
        ctxOriginal.fill();
      });

      // Crosshair lines
      ctxOriginal.strokeStyle = "#ffffff";
      ctxOriginal.lineWidth = 4;
      ctxOriginal.beginPath();
      ctxOriginal.moveTo(100, 10);
      ctxOriginal.lineTo(100, 190);
      ctxOriginal.moveTo(10, 100);
      ctxOriginal.lineTo(190, 100);
      ctxOriginal.stroke();
    }

    // Extract raw RGBA pixel data
    originalImageData = ctxOriginal.getImageData(0, 0, currentWidth, currentHeight);
    
    // Update stats UI
    metaOriginal.textContent = `${currentWidth} × ${currentHeight} px`;
    statOrigSize.textContent = `${(originalImageData.data.length).toLocaleString()} B`;
    
    resetEncryptedState();
    updateStatus(`Loaded <strong>"${type.toUpperCase()}"</strong> sample image (${currentWidth}×${currentHeight} px). Click <strong>"Encrypt Image"</strong> to view the ECB pattern leak.`, "info");
  }

  function resetEncryptedState() {
    ecbCipherBytes = null;
    gcmCipherBytes = null;
    ctxEcb.clearRect(0, 0, currentWidth, currentHeight);
    ctxGcm.clearRect(0, 0, currentWidth, currentHeight);
    placeholderEcb.classList.remove("hidden");
    placeholderGcm.classList.remove("hidden");
    decryptionSection.classList.add("hidden");
    btnDecrypt.disabled = true;
  }

  // --- 3. Encryption Pipeline (ECB + GCM) ---
  async function runEncryptionPipeline() {
    if (!originalImageData) return;

    const keyHex = inputKeyHex.value.trim();
    const keyBytes = hexToBytes(keyHex);

    updateStatus("Running AES-ECB block encryption and Web Crypto AES-GCM...", "info");

    const rawPixelBytes = new Uint8Array(originalImageData.data.buffer);
    const startTime = performance.now();

    // A. AES-ECB Path (Manual 16-byte block encryption)
    ecbCipherBytes = AES.ecbEncrypt(rawPixelBytes, keyBytes);

    // Render ECB Ciphertext Canvas
    // Note: We render ciphertext RGBA bytes to canvas with alpha forced to 255 for opaque color visualization
    const ecbImageData = ctxEcb.createImageData(currentWidth, currentHeight);
    for (let i = 0; i < ecbCipherBytes.length; i += 4) {
      ecbImageData.data[i]     = ecbCipherBytes[i];     // R
      ecbImageData.data[i + 1] = ecbCipherBytes[i + 1]; // G
      ecbImageData.data[i + 2] = ecbCipherBytes[i + 2]; // B
      ecbImageData.data[i + 3] = 255;                   // Force Opaque Alpha for crisp rendering
    }
    ctxEcb.putImageData(ecbImageData, 0, 0);
    placeholderEcb.classList.add("hidden");

    // B. AES-GCM Path (Web Crypto API directly)
    currentGcmIv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit random IV
    const gcmCryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    const gcmEncryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: currentGcmIv },
      gcmCryptoKey,
      rawPixelBytes
    );
    gcmCipherBytes = new Uint8Array(gcmEncryptedBuffer);

    // Render GCM Ciphertext Canvas
    const gcmImageData = ctxGcm.createImageData(currentWidth, currentHeight);
    for (let i = 0; i < rawPixelBytes.length; i += 4) {
      gcmImageData.data[i]     = gcmCipherBytes[i];
      gcmImageData.data[i + 1] = gcmCipherBytes[i + 1];
      gcmImageData.data[i + 2] = gcmCipherBytes[i + 2];
      gcmImageData.data[i + 3] = 255; // Force Opaque Alpha for crisp noise rendering
    }
    ctxGcm.putImageData(gcmImageData, 0, 0);
    placeholderGcm.classList.add("hidden");

    const elapsed = (performance.now() - startTime).toFixed(1);

    btnDecrypt.disabled = false;
    updateStatus(`⚡ Encryption complete in ${elapsed}ms! Notice how the silhouette is preserved in <strong>AES-ECB</strong> panel, while <strong>AES-GCM</strong> is pure noise. Click <strong>"Decrypt & Verify"</strong> to test recoverability.`, "warning");
  }

  // --- 4. Decryption Pipeline & Verification ---
  async function runDecryptionPipeline() {
    if (!ecbCipherBytes || !gcmCipherBytes) return;

    const keyHex = inputKeyHex.value.trim();
    const keyBytes = hexToBytes(keyHex);

    updateStatus("Decrypting ciphertexts and performing bit-exact byte verification...", "info");

    const rawOriginalBytes = new Uint8Array(originalImageData.data.buffer);

    // Decrypt ECB
    const decEcbBytes = AES.ecbDecrypt(ecbCipherBytes, keyBytes);

    // Render Decrypted ECB
    const decEcbImgData = ctxDecEcb.createImageData(currentWidth, currentHeight);
    decEcbImgData.data.set(decEcbBytes);
    ctxDecEcb.putImageData(decEcbImgData, 0, 0);

    // Decrypt GCM via Web Crypto API
    const gcmCryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    let decGcmBytes;
    try {
      const decryptedGcmBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: currentGcmIv },
        gcmCryptoKey,
        gcmCipherBytes
      );
      decGcmBytes = new Uint8Array(decryptedGcmBuffer);
    } catch (err) {
      console.error("GCM Decryption failed:", err);
      updateStatus("⚠️ GCM Decryption failed (Authentication tag mismatch).", "warning");
      return;
    }

    // Render Decrypted GCM
    const decGcmImgData = ctxDecGcm.createImageData(currentWidth, currentHeight);
    decGcmImgData.data.set(decGcmBytes);
    ctxDecGcm.putImageData(decGcmImgData, 0, 0);

    // Bit-exact verification against raw original
    let ecbMismatchCount = 0;
    for (let i = 0; i < rawOriginalBytes.length; i++) {
      if (decEcbBytes[i] !== rawOriginalBytes[i]) ecbMismatchCount++;
    }

    let gcmMismatchCount = 0;
    for (let i = 0; i < rawOriginalBytes.length; i++) {
      if (decGcmBytes[i] !== rawOriginalBytes[i]) gcmMismatchCount++;
    }

    // Update Verification UI
    document.getElementById("status-dec-ecb").innerHTML = ecbMismatchCount === 0
      ? `Match: <strong class="text-success">Exact Bit Match (0 byte diff)</strong>`
      : `Match: <strong class="text-danger">${ecbMismatchCount} byte mismatches!</strong>`;

    document.getElementById("status-dec-gcm").innerHTML = gcmMismatchCount === 0
      ? `Match: <strong class="text-success">Exact Bit Match (0 byte diff)</strong>`
      : `Match: <strong class="text-danger">${gcmMismatchCount} byte mismatches!</strong>`;

    decryptionSection.classList.remove("hidden");
    decryptionSection.scrollIntoView({ behavior: "smooth" });

    if (ecbMismatchCount === 0 && gcmMismatchCount === 0) {
      updateStatus("✅ <strong>Decryption Successful!</strong> Both ECB and GCM recovered the exact original image losslessly (0 byte difference). Proving both are valid ciphers, but ECB's lack of IV leaks spatial structure.", "success");
    } else {
      updateStatus("⚠️ Decryption mismatch detected during verification.", "warning");
    }
  }

  // --- 5. Interactive Pixel & Block Inspector ---
  function inspectPixelAt(event, canvasElement) {
    if (!originalImageData) return;

    const rect = canvasElement.getBoundingClientRect();
    const scaleX = currentWidth / rect.width;
    const scaleY = currentHeight / rect.height;

    const x = Math.floor((event.clientX - rect.left) * scaleX);
    const y = Math.floor((event.clientY - rect.top) * scaleY);

    if (x < 0 || x >= currentWidth || y < 0 || y >= currentHeight) return;

    const pixelIndex = y * currentWidth + x;
    const byteOffset = pixelIndex * 4;
    const blockIndex = Math.floor(byteOffset / 16);
    const blockStartByte = blockIndex * 16;

    inspectCoords.textContent = `X: ${x}, Y: ${y} (Block #${blockIndex})`;

    // Original RGBA
    const origData = originalImageData.data;
    const origR = origData[byteOffset].toString(16).padStart(2, "0");
    const origG = origData[byteOffset + 1].toString(16).padStart(2, "0");
    const origB = origData[byteOffset + 2].toString(16).padStart(2, "0");
    const origA = origData[byteOffset + 3].toString(16).padStart(2, "0");
    inspectOrigHex.textContent = `#${origR}${origG}${origB}${origA} [${origData[byteOffset]}, ${origData[byteOffset+1]}, ${origData[byteOffset+2]}, ${origData[byteOffset+3]}]`;

    // ECB Block Bytes
    if (ecbCipherBytes) {
      const ecbSlice = ecbCipherBytes.subarray(blockStartByte, blockStartByte + 16);
      inspectEcbHex.textContent = bytesToHex(ecbSlice.subarray(0, 8)) + " ...";
    } else {
      inspectEcbHex.textContent = "Not encrypted yet";
    }

    // GCM Bytes at offset
    if (gcmCipherBytes) {
      const gcmSlice = gcmCipherBytes.subarray(byteOffset, byteOffset + 16);
      inspectGcmHex.textContent = bytesToHex(gcmSlice.subarray(0, 8)) + " ...";
    } else {
      inspectGcmHex.textContent = "Not encrypted yet";
    }
  }

  // Attach inspector events to all three main canvases
  [canvasOriginal, canvasEcb, canvasGcm].forEach(canvas => {
    canvas.addEventListener("mousemove", (e) => inspectPixelAt(e, canvas));
  });

  // --- 6. Custom Image Upload Handler ---
  imageUpload.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = () => {
        // Target canvas size (max 256x256 for fast visual demo)
        let w = img.width;
        let h = img.height;
        const maxDim = 250;

        if (w > maxDim || h > maxDim) {
          if (w > h) {
            h = Math.round((h * maxDim) / w);
            w = maxDim;
          } else {
            w = Math.round((w * maxDim) / h);
            h = maxDim;
          }
        }

        currentWidth = w;
        currentHeight = h;

        canvasOriginal.width = currentWidth;
        canvasOriginal.height = currentHeight;
        canvasEcb.width = currentWidth;
        canvasEcb.height = currentHeight;
        canvasGcm.width = currentWidth;
        canvasGcm.height = currentHeight;
        canvasDecEcb.width = currentWidth;
        canvasDecEcb.height = currentHeight;
        canvasDecGcm.width = currentWidth;
        canvasDecGcm.height = currentHeight;

        ctxOriginal.clearRect(0, 0, currentWidth, currentHeight);
        ctxOriginal.drawImage(img, 0, 0, currentWidth, currentHeight);

        originalImageData = ctxOriginal.getImageData(0, 0, currentWidth, currentHeight);

        metaOriginal.textContent = `${currentWidth} × ${currentHeight} px`;
        statOrigSize.textContent = `${(originalImageData.data.length).toLocaleString()} B`;

        // Highlight custom upload button
        document.querySelectorAll(".btn-sample").forEach(b => b.classList.remove("active"));
        resetEncryptedState();

        updateStatus(`Loaded custom image "${file.name}" (${currentWidth}×${currentHeight} px). Click <strong>"Encrypt Image"</strong> to run cipher mode visual comparison.`, "info");
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  });

  // --- 7. Event Listeners ---
  document.querySelectorAll(".btn-sample").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".btn-sample").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      loadPresetSample(btn.dataset.sample);
    });
  });

  btnGenKey.addEventListener("click", () => {
    const randomKey = crypto.getRandomValues(new Uint8Array(16));
    inputKeyHex.value = bytesToHex(randomKey);
    updateStatus("Generated new random 128-bit AES Key.", "info");
    if (ecbCipherBytes) {
      runEncryptionPipeline();
    }
  });

  btnEncrypt.addEventListener("click", runEncryptionPipeline);
  btnDecrypt.addEventListener("click", runDecryptionPipeline);

  btnReset.addEventListener("click", () => {
    loadPresetSample("shield");
    document.querySelectorAll(".btn-sample").forEach(b => b.classList.remove("active"));
    document.getElementById("btn-sample-shield").classList.add("active");
  });

  // Load default "shield" preset on startup
  loadPresetSample("shield");
});
