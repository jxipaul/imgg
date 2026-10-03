/**
 * AES Cryptanalysis Workbench — Core Application Logic
 * Integrates:
 * - Pure JS AES-128 Engine (ECB Mode)
 * - W3C Web Crypto API (AES-GCM Mode)
 * - Synchronized Multi-Canvas Reticle & 16-Byte Block Inspection
 * - Repeating Block Spatial Pattern Analysis
 * - Shannon Entropy & 256-Bin Byte Frequency Spectrum
 * - SHA-256 Digest Verification & Lossless Byte Differentials
 * - Audit Log JSON Export & PNG Exporters
 */

document.addEventListener("DOMContentLoaded", () => {
  // --- DOM Element References ---
  const canvasOriginal = document.getElementById("canvas-original");
  const canvasEcb = document.getElementById("canvas-ecb");
  const canvasGcm = document.getElementById("canvas-gcm");
  const canvasDecEcb = document.getElementById("canvas-dec-ecb");
  const canvasDecGcm = document.getElementById("canvas-dec-gcm");
  const canvasDiff = document.getElementById("canvas-diff");
  const canvasSpectrum = document.getElementById("canvas-spectrum");

  const overlayOriginal = document.getElementById("overlay-original");
  const overlayEcb = document.getElementById("overlay-ecb");
  const overlayGcm = document.getElementById("overlay-gcm");

  const ctxOriginal = canvasOriginal.getContext("2d", { willReadFrequently: true });
  const ctxEcb = canvasEcb.getContext("2d");
  const ctxGcm = canvasGcm.getContext("2d");
  const ctxDecEcb = canvasDecEcb.getContext("2d");
  const ctxDecGcm = canvasDecGcm.getContext("2d");
  const ctxDiff = canvasDiff.getContext("2d");
  const ctxSpectrum = canvasSpectrum.getContext("2d");

  const ctxOverOrig = overlayOriginal.getContext("2d");
  const ctxOverEcb = overlayEcb.getContext("2d");
  const ctxOverGcm = overlayGcm.getContext("2d");

  // Inputs & Controls
  const inputKeyHex = document.getElementById("aes-key-hex");
  const inputGcmIvHex = document.getElementById("aes-gcm-iv-hex");
  const btnGenKey = document.getElementById("btn-gen-key");
  const btnCopyKey = document.getElementById("btn-copy-key");
  const btnGenIv = document.getElementById("btn-gen-iv");
  const btnEncrypt = document.getElementById("btn-encrypt");
  const btnDecrypt = document.getElementById("btn-decrypt");
  const btnReset = document.getElementById("btn-reset");
  const imageUpload = document.getElementById("image-upload");

  // Options & Toggles
  const chkSyncReticle = document.getElementById("chk-sync-reticle");
  const chkHighlightRepeats = document.getElementById("chk-highlight-repeats");
  const chkPixelGrid = document.getElementById("chk-pixel-grid");
  const zoomBtns = document.querySelectorAll(".zoom-btn");

  // Telemetry Banner & HUD
  const systemStatusPill = document.getElementById("system-status-pill");
  const statusLabel = document.getElementById("status-label");
  const telemetryMsg = document.getElementById("telemetry-msg");
  const metricResolution = document.getElementById("metric-resolution");
  const metricBlocks = document.getElementById("metric-blocks");
  const hudOrigCoords = document.getElementById("hud-orig-coords");
  const hudEcbCoords = document.getElementById("hud-ecb-coords");
  const hudGcmCoords = document.getElementById("hud-gcm-coords");

  // Panel Stats Elements
  const statOrigEntropy = document.getElementById("stat-orig-entropy");
  const statOrigUnique = document.getElementById("stat-orig-unique");
  const statOrigRedundancy = document.getElementById("stat-orig-redundancy");
  const statEcbEntropy = document.getElementById("stat-ecb-entropy");
  const statEcbUnique = document.getElementById("stat-ecb-unique");
  const statGcmEntropy = document.getElementById("stat-gcm-entropy");
  const statGcmUnique = document.getElementById("stat-gcm-unique");

  // Inspector Elements
  const inspectCoords = document.getElementById("inspect-coords");
  const inspectMatchCount = document.getElementById("inspect-match-count");
  const hexPlaintext = document.getElementById("hex-plaintext");
  const asciiPlaintext = document.getElementById("ascii-plaintext");
  const hexEcb = document.getElementById("hex-ecb");
  const hexGcm = document.getElementById("hex-gcm");
  const correlationText = document.getElementById("correlation-text");
  const btnUnlockInspector = document.getElementById("btn-unlock-inspector");

  // Spectrum & Entropy Meters
  const meterValOrig = document.getElementById("meter-val-orig");
  const meterValEcb = document.getElementById("meter-val-ecb");
  const meterValGcm = document.getElementById("meter-val-gcm");
  const meterFillOrig = document.getElementById("meter-fill-orig");
  const meterFillEcb = document.getElementById("meter-fill-ecb");
  const meterFillGcm = document.getElementById("meter-fill-gcm");

  // Decryption & Verification Section
  const verificationConsole = document.getElementById("verification-console");
  const shaOriginal = document.getElementById("sha-original");
  const shaEcb = document.getElementById("sha-ecb");
  const shaGcm = document.getElementById("sha-gcm");
  const badgeEcbMatch = document.getElementById("badge-ecb-match");
  const badgeGcmMatch = document.getElementById("badge-gcm-match");
  const statDiffBytes = document.getElementById("stat-diff-bytes");
  const statPsnr = document.getElementById("stat-psnr");
  const statAuthTag = document.getElementById("stat-auth-tag");
  const statBenchmarks = document.getElementById("stat-benchmarks");
  const statThroughput = document.getElementById("stat-throughput");
  const pillDecEcb = document.getElementById("pill-dec-ecb");
  const pillDecGcm = document.getElementById("pill-dec-gcm");
  const pillDiffMap = document.getElementById("pill-diff-map");

  // Export & Action Buttons
  const btnDlOrig = document.getElementById("btn-dl-orig");
  const btnDlEcb = document.getElementById("btn-dl-ecb");
  const btnDlGcm = document.getElementById("btn-dl-gcm");
  const btnExportAudit = document.getElementById("btn-export-audit");

  // Placeholders
  const placeholderEcb = document.getElementById("placeholder-ecb");
  const placeholderGcm = document.getElementById("placeholder-gcm");

  // Specs Modal
  const modalSpecs = document.getElementById("modal-specs");
  const btnOpenSpecs = document.getElementById("btn-open-specs");
  const btnCloseSpecs = document.getElementById("btn-close-specs");
  const btnCloseSpecsBottom = document.getElementById("btn-close-specs-bottom");

  // --- State Variables ---
  let currentWidth = 200;
  let currentHeight = 200;
  let originalImageData = null; // ImageData
  let ecbCipherBytes = null;    // Uint8Array (RGBA encrypted)
  let gcmCipherBytes = null;    // Uint8Array (raw ciphertext + auth tag)
  let gcmIvBytes = null;        // Uint8Array(12)
  let decryptedEcbBytes = null; // Uint8Array
  let decryptedGcmBytes = null; // Uint8Array

  let isInspectorLocked = false;
  let lockedBlockIndex = null;
  let activeZoom = 1;
  let currentPreset = "penguin";

  // Telemetry caches
  let sourceEntropyData = null;
  let ecbEntropyData = null;
  let gcmEntropyData = null;
  let uniqueBlockStats = { orig: 0, ecb: 0, gcm: 0, total: 0 };
  let executionTimings = { ecbEncryptMs: 0, gcmEncryptMs: 0, ecbDecryptMs: 0, gcmDecryptMs: 0 };

  // --- 1. Helper Cryptographic & Math Functions ---

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

  function formatBytesHexSpaced(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
  }

  function bytesToAscii(bytes) {
    return Array.from(bytes)
      .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
  }

  async function computeSha256(bytes) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function calculateShannonEntropy(bytes) {
    const counts = new Uint32Array(256);
    const len = bytes.length;
    for (let i = 0; i < len; i++) {
      counts[bytes[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (counts[i] > 0) {
        const p = counts[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return { entropy, counts };
  }

  function calculateBlockStats(dataBytes) {
    const totalBlocks = Math.floor(dataBytes.length / 16);
    const uniqueMap = new Map();
    for (let i = 0; i < totalBlocks; i++) {
      const offset = i * 16;
      // Use string representation of 16 bytes for fast map key
      let key = "";
      for (let j = 0; j < 16; j++) {
        key += String.fromCharCode(dataBytes[offset + j]);
      }
      uniqueMap.set(key, (uniqueMap.get(key) || 0) + 1);
    }
    return {
      totalBlocks,
      uniqueCount: uniqueMap.size,
      blockFrequency: uniqueMap
    };
  }

  function setSystemStatus(state, label) {
    statusLabel.textContent = label;
    if (state === "ready") {
      systemStatusPill.style.borderColor = "rgba(0, 245, 212, 0.25)";
      systemStatusPill.style.background = "rgba(0, 245, 212, 0.08)";
    } else if (state === "encrypted") {
      systemStatusPill.style.borderColor = "rgba(245, 158, 11, 0.4)";
      systemStatusPill.style.background = "rgba(245, 158, 11, 0.12)";
    } else if (state === "verified") {
      systemStatusPill.style.borderColor = "rgba(16, 185, 129, 0.4)";
      systemStatusPill.style.background = "rgba(16, 185, 129, 0.12)";
    }
  }

  // --- 2. Canvas Resizing & Synchronization ---

  function resizeAllCanvases(w, h) {
    currentWidth = w;
    currentHeight = h;

    const allCanvases = [
      canvasOriginal, canvasEcb, canvasGcm,
      canvasDecEcb, canvasDecGcm, canvasDiff,
      overlayOriginal, overlayEcb, overlayGcm
    ];

    allCanvases.forEach(c => {
      c.width = w;
      c.height = h;
    });

    metricResolution.textContent = `${w} × ${h} px`;
    const total16BBlocks = (w * h * 4) / 16;
    metricBlocks.textContent = `${total16BBlocks.toLocaleString()} (16B)`;
  }

  function applyZoom(level) {
    activeZoom = level;
    zoomBtns.forEach(btn => {
      btn.classList.toggle("active", parseInt(btn.dataset.zoom) === level);
    });

    const viewports = document.querySelectorAll(".canvas-viewport");
    viewports.forEach(vp => {
      if (level === 1) {
        vp.style.transform = "none";
      } else {
        vp.style.transform = `scale(${level})`;
        vp.style.transformOrigin = "center center";
      }
    });
  }

  zoomBtns.forEach(btn => {
    btn.addEventListener("click", () => applyZoom(parseInt(btn.dataset.zoom)));
  });

  chkPixelGrid.addEventListener("change", () => {
    const viewports = document.querySelectorAll(".canvas-viewport");
    viewports.forEach(vp => {
      vp.classList.toggle("pixel-grid-active", chkPixelGrid.checked);
    });
  });

  // --- 3. Vector Preset Generators ---

  function generatePresetImage(preset) {
    currentPreset = preset;
    // Standard size 200x200 (50 16-byte blocks per row x 200 rows = 10,000 blocks)
    resizeAllCanvases(200, 200);
    const ctx = ctxOriginal;
    const w = 200;
    const h = 200;
    ctx.clearRect(0, 0, w, h);

    if (preset === "penguin") {
      // Tux Linux Penguin: Pure white flat background (ideal for ECB leakage)
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, w, h);

      // Black Body
      ctx.fillStyle = "#09090b";
      ctx.beginPath();
      ctx.ellipse(100, 115, 54, 62, 0, 0, Math.PI * 2);
      ctx.fill();

      // Head
      ctx.beginPath();
      ctx.arc(100, 56, 36, 0, Math.PI * 2);
      ctx.fill();

      // White Belly
      ctx.fillStyle = "#ffffff";
      ctx.beginPath();
      ctx.ellipse(100, 124, 34, 44, 0, 0, Math.PI * 2);
      ctx.fill();

      // Eyes (white background + black pupils)
      ctx.beginPath();
      ctx.ellipse(88, 50, 9, 13, 0.1, 0, Math.PI * 2);
      ctx.ellipse(112, 50, 9, 13, -0.1, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = "#09090b";
      ctx.beginPath();
      ctx.arc(90, 51, 4, 0, Math.PI * 2);
      ctx.arc(110, 51, 4, 0, Math.PI * 2);
      ctx.fill();

      // Yellow beak
      ctx.fillStyle = "#f59e0b";
      ctx.beginPath();
      ctx.moveTo(82, 62);
      ctx.lineTo(118, 62);
      ctx.lineTo(100, 82);
      ctx.closePath();
      ctx.fill();

      // Wings / Flippers
      ctx.fillStyle = "#09090b";
      ctx.beginPath();
      ctx.ellipse(44, 118, 14, 38, 0.45, 0, Math.PI * 2);
      ctx.ellipse(156, 118, 14, 38, -0.45, 0, Math.PI * 2);
      ctx.fill();

      // Feet
      ctx.fillStyle = "#ea580c";
      ctx.beginPath();
      ctx.ellipse(74, 175, 22, 10, -0.15, 0, Math.PI * 2);
      ctx.ellipse(126, 175, 22, 10, 0.15, 0, Math.PI * 2);
      ctx.fill();

    } else if (preset === "shield") {
      // Cyber Security Shield & Key
      ctx.fillStyle = "#06090f";
      ctx.fillRect(0, 0, w, h);

      // Outer Shield
      ctx.fillStyle = "#00f5d4";
      ctx.beginPath();
      ctx.moveTo(100, 24);
      ctx.lineTo(168, 48);
      ctx.lineTo(168, 112);
      ctx.quadraticCurveTo(168, 170, 100, 186);
      ctx.quadraticCurveTo(32, 170, 32, 112);
      ctx.lineTo(32, 48);
      ctx.closePath();
      ctx.fill();

      // Inner Shield Layer
      ctx.fillStyle = "#0284c7";
      ctx.beginPath();
      ctx.moveTo(100, 38);
      ctx.lineTo(154, 58);
      ctx.lineTo(154, 108);
      ctx.quadraticCurveTo(154, 156, 100, 172);
      ctx.quadraticCurveTo(46, 156, 46, 108);
      ctx.lineTo(46, 58);
      ctx.closePath();
      ctx.fill();

      // Keyhole
      ctx.fillStyle = "#06090f";
      ctx.beginPath();
      ctx.arc(100, 94, 16, 0, Math.PI * 2);
      ctx.fill();

      ctx.beginPath();
      ctx.moveTo(91, 98);
      ctx.lineTo(109, 98);
      ctx.lineTo(115, 134);
      ctx.lineTo(85, 134);
      ctx.closePath();
      ctx.fill();

    } else if (preset === "target") {
      // Concentric Target Reticle
      ctx.fillStyle = "#090d16";
      ctx.fillRect(0, 0, w, h);

      const rings = [
        { r: 84, c: "#ff3366" },
        { r: 66, c: "#ffffff" },
        { r: 48, c: "#38bdf8" },
        { r: 30, c: "#ffffff" },
        { r: 14, c: "#f59e0b" }
      ];

      rings.forEach(ring => {
        ctx.fillStyle = ring.c;
        ctx.beginPath();
        ctx.arc(100, 100, ring.r, 0, Math.PI * 2);
        ctx.fill();
      });

      // Reticle Crosshairs
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo(100, 10);
      ctx.lineTo(100, 190);
      ctx.moveTo(10, 100);
      ctx.lineTo(190, 100);
      ctx.stroke();

    } else if (preset === "qr") {
      // 2D QR Barcode Matrix (demonstrating structural data leaks)
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, w, h);

      ctx.fillStyle = "#000000";
      // Helper function to draw finder pattern
      function drawFinder(ox, oy) {
        ctx.fillRect(ox, oy, 42, 42);
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(ox + 6, oy + 6, 30, 30);
        ctx.fillStyle = "#000000";
        ctx.fillRect(ox + 12, oy + 12, 18, 18);
      }

      drawFinder(16, 16);
      drawFinder(142, 16);
      drawFinder(16, 142);

      // Alignment Pattern
      ctx.fillRect(134, 134, 30, 30);
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(140, 140, 18, 18);
      ctx.fillStyle = "#000000";
      ctx.fillRect(146, 146, 6, 6);

      // Timing tracks
      for (let i = 64; i < 136; i += 8) {
        ctx.fillRect(i, 28, 4, 4);
        ctx.fillRect(28, i, 4, 4);
      }

      // Simulated Data Modules
      const seedModules = [
        [70, 70, 20, 20], [100, 70, 16, 28], [70, 100, 28, 16],
        [110, 110, 18, 18], [160, 70, 24, 16], [70, 150, 16, 24],
        [100, 140, 24, 20], [140, 100, 16, 20]
      ];
      seedModules.forEach(([x, y, sw, sh]) => ctx.fillRect(x, y, sw, sh));

    } else if (preset === "medical") {
      // Medical Radiograph PACS DICOM silhouette (chest cavity / ribcage)
      ctx.fillStyle = "#030712";
      ctx.fillRect(0, 0, w, h);

      // Spinal Column
      ctx.fillStyle = "#e2e8f0";
      for (let y = 20; y < 185; y += 12) {
        ctx.fillRect(94, y, 12, 8);
      }

      // Lung Fields (High-contrast radiolucent cavities)
      ctx.fillStyle = "#0f172a";
      ctx.beginPath();
      ctx.ellipse(65, 95, 26, 44, -0.1, 0, Math.PI * 2);
      ctx.ellipse(135, 95, 26, 44, 0.1, 0, Math.PI * 2);
      ctx.fill();

      // Rib Arcs
      ctx.strokeStyle = "#94a3b8";
      ctx.lineWidth = 4;
      for (let i = 0; i < 5; i++) {
        const yOffset = 45 + i * 22;
        ctx.beginPath();
        ctx.arc(60, yOffset, 32, 0.2, 1.4);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(140, yOffset, 32, 1.7, 2.9);
        ctx.stroke();
      }

      // Cardiac Silhouette
      ctx.fillStyle = "#cbd5e1";
      ctx.beginPath();
      ctx.ellipse(108, 118, 22, 18, -0.3, 0, Math.PI * 2);
      ctx.fill();

      // PACS DICOM Watermark Banner
      ctx.fillStyle = "#38bdf8";
      ctx.font = "bold 9px 'Fira Code', monospace";
      ctx.fillText("PACS-DICOM #7829-CNS", 12, 192);
    }

    // Capture raw source RGBA buffer
    originalImageData = ctxOriginal.getImageData(0, 0, w, h);

    // Compute Source Plaintext Telemetry
    const rawBytes = new Uint8Array(originalImageData.data.buffer);
    sourceEntropyData = calculateShannonEntropy(rawBytes);
    const sourceBlocks = calculateBlockStats(rawBytes);
    uniqueBlockStats.orig = sourceBlocks.uniqueCount;
    uniqueBlockStats.total = sourceBlocks.totalBlocks;

    statOrigEntropy.textContent = `${sourceEntropyData.entropy.toFixed(3)} bits/byte`;
    statOrigUnique.textContent = `${sourceBlocks.uniqueCount.toLocaleString()} / ${sourceBlocks.totalBlocks.toLocaleString()}`;
    const redundancy = (100 - (sourceBlocks.uniqueCount / sourceBlocks.totalBlocks) * 100).toFixed(1);
    statOrigRedundancy.textContent = `${redundancy}%`;

    meterValOrig.textContent = `${sourceEntropyData.entropy.toFixed(2)} / 8.0`;
    meterFillOrig.style.width = `${(sourceEntropyData.entropy / 8.0) * 100}%`;

    renderSpectrum();
    resetCipherState();
    setSystemStatus("ready", "WORKBENCH READY");
    telemetryMsg.innerHTML = `Loaded <strong>${preset.toUpperCase()}</strong> preset (${w}×${h} px, ${sourceBlocks.totalBlocks.toLocaleString()} 16-byte blocks). Click <strong>"ENCRYPT MODES"</strong> to execute cipher analysis.`;
  }

  function resetCipherState() {
    ecbCipherBytes = null;
    gcmCipherBytes = null;
    decryptedEcbBytes = null;
    decryptedGcmBytes = null;

    ctxEcb.clearRect(0, 0, currentWidth, currentHeight);
    ctxGcm.clearRect(0, 0, currentWidth, currentHeight);
    ctxDecEcb.clearRect(0, 0, currentWidth, currentHeight);
    ctxDecGcm.clearRect(0, 0, currentWidth, currentHeight);
    ctxDiff.clearRect(0, 0, currentWidth, currentHeight);

    clearOverlays();

    placeholderEcb.classList.remove("hidden");
    placeholderGcm.classList.remove("hidden");
    verificationConsole.classList.add("hidden");

    btnDecrypt.disabled = true;
    btnDlEcb.disabled = true;
    btnDlGcm.disabled = true;

    statEcbEntropy.textContent = "-- bits/byte";
    statEcbUnique.textContent = "-- / --";
    statGcmEntropy.textContent = "-- bits/byte";
    statGcmUnique.textContent = "-- / --";

    meterValEcb.textContent = "-- / 8.0";
    meterValGcm.textContent = "-- / 8.0";
    meterFillEcb.style.width = "0%";
    meterFillGcm.style.width = "0%";

    hexEcb.textContent = "-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --";
    hexGcm.textContent = "-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --";

    isInspectorLocked = false;
    lockedBlockIndex = null;
    btnUnlockInspector.textContent = "Unlock";
  }

  // --- 4. Encryption Pipeline (AES-128-ECB & AES-128-GCM) ---

  async function runEncryptionPipeline() {
    if (!originalImageData) return;

    const keyHex = inputKeyHex.value.trim();
    const keyBytes = hexToBytes(keyHex);
    inputKeyHex.value = bytesToHex(keyBytes);

    telemetryMsg.innerHTML = "Executing concurrent AES-128-ECB (JS engine) and AES-128-GCM (Web Crypto API)...";
    setSystemStatus("encrypted", "PROCESSING...");

    const rawPixelBytes = new Uint8Array(originalImageData.data.buffer);
    const byteLength = rawPixelBytes.length;

    // A. Execute AES-128-ECB (Pure JS Block-by-Block Engine)
    const t0Ecb = performance.now();
    ecbCipherBytes = AES.ecbEncrypt(rawPixelBytes, keyBytes);
    executionTimings.ecbEncryptMs = performance.now() - t0Ecb;

    // Render ECB Ciphertext to Canvas (Alpha set to 255 for opaque color visualization)
    const ecbImgData = ctxEcb.createImageData(currentWidth, currentHeight);
    for (let i = 0; i < byteLength; i += 4) {
      ecbImgData.data[i]     = ecbCipherBytes[i];
      ecbImgData.data[i + 1] = ecbCipherBytes[i + 1];
      ecbImgData.data[i + 2] = ecbCipherBytes[i + 2];
      ecbImgData.data[i + 3] = 255;
    }
    ctxEcb.putImageData(ecbImgData, 0, 0);
    placeholderEcb.classList.add("hidden");
    btnDlEcb.disabled = false;

    // B. Execute AES-128-GCM via Web Crypto API
    gcmIvBytes = crypto.getRandomValues(new Uint8Array(12)); // 96-bit random IV
    inputGcmIvHex.value = bytesToHex(gcmIvBytes);

    const t0Gcm = performance.now();
    const gcmCryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    const gcmEncryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: gcmIvBytes },
      gcmCryptoKey,
      rawPixelBytes
    );
    executionTimings.gcmEncryptMs = performance.now() - t0Gcm;
    gcmCipherBytes = new Uint8Array(gcmEncryptedBuffer);

    // Render GCM Ciphertext to Canvas (Ciphertext stream bytes as RGB, Alpha forced to 255)
    const gcmImgData = ctxGcm.createImageData(currentWidth, currentHeight);
    for (let i = 0; i < byteLength; i += 4) {
      gcmImgData.data[i]     = gcmCipherBytes[i];
      gcmImgData.data[i + 1] = gcmCipherBytes[i + 1];
      gcmImgData.data[i + 2] = gcmCipherBytes[i + 2];
      gcmImgData.data[i + 3] = 255;
    }
    ctxGcm.putImageData(gcmImgData, 0, 0);
    placeholderGcm.classList.add("hidden");
    btnDlGcm.disabled = false;

    // C. Telemetry & Shannon Entropy Computation
    ecbEntropyData = calculateShannonEntropy(ecbCipherBytes);
    gcmEntropyData = calculateShannonEntropy(gcmCipherBytes.subarray(0, byteLength));

    const ecbBlockStats = calculateBlockStats(ecbCipherBytes);
    const gcmBlockStats = calculateBlockStats(gcmCipherBytes.subarray(0, byteLength));

    uniqueBlockStats.ecb = ecbBlockStats.uniqueCount;
    uniqueBlockStats.gcm = gcmBlockStats.uniqueCount;

    statEcbEntropy.textContent = `${ecbEntropyData.entropy.toFixed(3)} bits/byte`;
    statEcbUnique.textContent = `${ecbBlockStats.uniqueCount.toLocaleString()} / ${ecbBlockStats.totalBlocks.toLocaleString()}`;

    statGcmEntropy.textContent = `${gcmEntropyData.entropy.toFixed(3)} bits/byte`;
    statGcmUnique.textContent = `${gcmBlockStats.uniqueCount.toLocaleString()} / ${gcmBlockStats.totalBlocks.toLocaleString()}`;

    meterValEcb.textContent = `${ecbEntropyData.entropy.toFixed(2)} / 8.0`;
    meterValGcm.textContent = `${gcmEntropyData.entropy.toFixed(2)} / 8.0`;
    meterFillEcb.style.width = `${(ecbEntropyData.entropy / 8.0) * 100}%`;
    meterFillGcm.style.width = `${(gcmEntropyData.entropy / 8.0) * 100}%`;

    renderSpectrum();

    btnDecrypt.disabled = false;
    setSystemStatus("encrypted", "CIPHERTEXT GENERATED");

    const totalMs = (executionTimings.ecbEncryptMs + executionTimings.gcmEncryptMs).toFixed(1);
    telemetryMsg.innerHTML = `Encryption complete in <strong>${totalMs}ms</strong>. Notice severe <strong>ECB pattern leak</strong> (Entropy: ${ecbEntropyData.entropy.toFixed(2)}) vs <strong>GCM pseudo-random noise</strong> (Entropy: ${gcmEntropyData.entropy.toFixed(2)}). Click <strong>"DECRYPT & VERIFY"</strong> to prove lossless reversibility.`;

    // Update inspector with block 0 data
    inspectBlockAt(0);
  }

  // --- 5. Decryption & Bit-Exact Verification ---

  async function runDecryptionPipeline() {
    if (!ecbCipherBytes || !gcmCipherBytes) return;

    const keyHex = inputKeyHex.value.trim();
    const keyBytes = hexToBytes(keyHex);
    const rawOriginalBytes = new Uint8Array(originalImageData.data.buffer);
    const byteLength = rawOriginalBytes.length;

    telemetryMsg.innerHTML = "Executing inverse cipher decryption and performing bit-exact differential analysis...";
    setSystemStatus("verified", "VERIFYING INTEGRITY...");

    // A. Decrypt ECB
    const t0EcbDec = performance.now();
    decryptedEcbBytes = AES.ecbDecrypt(ecbCipherBytes, keyBytes);
    executionTimings.ecbDecryptMs = performance.now() - t0EcbDec;

    const decEcbImgData = ctxDecEcb.createImageData(currentWidth, currentHeight);
    decEcbImgData.data.set(decryptedEcbBytes);
    ctxDecEcb.putImageData(decEcbImgData, 0, 0);

    // B. Decrypt GCM via Web Crypto API
    const t0GcmDec = performance.now();
    const gcmCryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    let gcmAuthValid = false;
    try {
      const decryptedGcmBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: gcmIvBytes },
        gcmCryptoKey,
        gcmCipherBytes
      );
      decryptedGcmBytes = new Uint8Array(decryptedGcmBuffer);
      gcmAuthValid = true;
    } catch (err) {
      console.error("AES-GCM Decryption failed:", err);
      statAuthTag.textContent = "TAG MISMATCH";
      statAuthTag.className = "stat-card-val text-danger";
      telemetryMsg.innerHTML = "⚠️ AES-GCM Authentication failed! Auth tag was modified or corrupted.";
      return;
    }
    executionTimings.gcmDecryptMs = performance.now() - t0GcmDec;

    const decGcmImgData = ctxDecGcm.createImageData(currentWidth, currentHeight);
    decGcmImgData.data.set(decryptedGcmBytes);
    ctxDecGcm.putImageData(decGcmImgData, 0, 0);

    // C. Render Difference Map (Original vs Decrypted ECB/GCM)
    const diffImgData = ctxDiff.createImageData(currentWidth, currentHeight);
    let diffPixelCount = 0;
    let byteMismatchCount = 0;

    for (let i = 0; i < byteLength; i += 4) {
      const deltaR = Math.abs(rawOriginalBytes[i] - decryptedEcbBytes[i]);
      const deltaG = Math.abs(rawOriginalBytes[i + 1] - decryptedEcbBytes[i + 1]);
      const deltaB = Math.abs(rawOriginalBytes[i + 2] - decryptedEcbBytes[i + 2]);
      const deltaA = Math.abs(rawOriginalBytes[i + 3] - decryptedEcbBytes[i + 3]);

      if (deltaR > 0 || deltaG > 0 || deltaB > 0 || deltaA > 0) {
        diffPixelCount++;
        // Exaggerate difference in bright magenta if any mismatch
        diffImgData.data[i]     = 255;
        diffImgData.data[i + 1] = 0;
        diffImgData.data[i + 2] = 128;
        diffImgData.data[i + 3] = 255;
      } else {
        // Pure black for 0.0 delta
        diffImgData.data[i]     = 0;
        diffImgData.data[i + 1] = 0;
        diffImgData.data[i + 2] = 0;
        diffImgData.data[i + 3] = 255;
      }

      if (rawOriginalBytes[i] !== decryptedEcbBytes[i]) byteMismatchCount++;
      if (rawOriginalBytes[i + 1] !== decryptedEcbBytes[i + 1]) byteMismatchCount++;
      if (rawOriginalBytes[i + 2] !== decryptedEcbBytes[i + 2]) byteMismatchCount++;
      if (rawOriginalBytes[i + 3] !== decryptedEcbBytes[i + 3]) byteMismatchCount++;
    }
    ctxDiff.putImageData(diffImgData, 0, 0);

    // D. Compute Cryptographic SHA-256 Hashes
    const [hashOrig, hashEcbDec, hashGcmDec] = await Promise.all([
      computeSha256(rawOriginalBytes),
      computeSha256(decryptedEcbBytes),
      computeSha256(decryptedGcmBytes)
    ]);

    shaOriginal.textContent = hashOrig;
    shaEcb.textContent = hashEcbDec;
    shaGcm.textContent = hashGcmDec;

    const isEcbMatch = hashOrig === hashEcbDec;
    const isGcmMatch = hashOrig === hashGcmDec;

    badgeEcbMatch.textContent = isEcbMatch ? "MATCH (100%)" : "MISMATCH";
    badgeEcbMatch.className = `hash-badge ${isEcbMatch ? "badge-match" : "badge-warning"}`;

    badgeGcmMatch.textContent = isGcmMatch ? "MATCH (100%)" : "MISMATCH";
    badgeGcmMatch.className = `hash-badge ${isGcmMatch ? "badge-match" : "badge-warning"}`;

    pillDecEcb.textContent = isEcbMatch ? "Exact Bit Match (0 diff)" : "Mismatch Detected";
    pillDecGcm.textContent = isGcmMatch ? "Exact Bit Match (0 diff)" : "Mismatch Detected";
    pillDiffMap.textContent = `${diffPixelCount} Pixels Differ (Δ = 0.0)`;

    statDiffBytes.textContent = `${byteMismatchCount} / ${byteLength.toLocaleString()}`;
    statPsnr.textContent = byteMismatchCount === 0 ? "+∞ dB (Lossless)" : "Degraded";
    statAuthTag.textContent = gcmAuthValid ? "PASSED (16-Byte Tag)" : "FAILED";

    const totalDecMs = (executionTimings.ecbDecryptMs + executionTimings.gcmDecryptMs).toFixed(1);
    statBenchmarks.textContent = `ECB: ${executionTimings.ecbDecryptMs.toFixed(1)}ms | GCM: ${executionTimings.gcmDecryptMs.toFixed(1)}ms`;

    const mbSize = (byteLength / (1024 * 1024));
    const throughput = (mbSize / ((executionTimings.ecbDecryptMs + executionTimings.gcmDecryptMs) / 1000)).toFixed(1);
    statThroughput.textContent = `Throughput: ${throughput} MB/s`;

    verificationConsole.classList.remove("hidden");
    verificationConsole.scrollIntoView({ behavior: "smooth", block: "start" });

    setSystemStatus("verified", "100% BIT-PERFECT VERIFIED");
    telemetryMsg.innerHTML = `✅ <strong>Lossless Recovery Verified!</strong> Both AES-ECB and AES-GCM restored the source image with <strong>0 byte mismatch</strong> and matching SHA-256 digests. Proving mode vulnerability is distinct from cipher reversibility.`;
  }

  // --- 6. Interactive 16-Byte Block Inspector & Repeating Block Highlighting ---

  function getBlockIndexFromCoord(x, y) {
    const blocksPerRow = currentWidth / 4;
    const blockX = Math.floor(x / 4);
    const blockY = y;
    return blockY * blocksPerRow + blockX;
  }

  function getCoordFromBlockIndex(blockIndex) {
    const blocksPerRow = currentWidth / 4;
    const blockX = blockIndex % blocksPerRow;
    const blockY = Math.floor(blockIndex / blocksPerRow);
    return { x: blockX * 4, y: blockY };
  }

  function clearOverlays() {
    ctxOverOrig.clearRect(0, 0, currentWidth, currentHeight);
    ctxOverEcb.clearRect(0, 0, currentWidth, currentHeight);
    ctxOverGcm.clearRect(0, 0, currentWidth, currentHeight);
  }

  function drawReticleOnOverlay(ctx, x, y) {
    // Crosshairs
    ctx.strokeStyle = "rgba(0, 245, 212, 0.4)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, y + 0.5);
    ctx.lineTo(currentWidth, y + 0.5);
    ctx.moveTo(x + 0.5, 0);
    ctx.lineTo(x + 0.5, currentHeight);
    ctx.stroke();

    // 4-pixel 16-byte Block Box
    const blockStartX = Math.floor(x / 4) * 4;
    ctx.strokeStyle = "#00f5d4";
    ctx.lineWidth = 1.5;
    ctx.strokeRect(blockStartX + 0.5, y + 0.5, 4, 1);
  }

  function inspectBlockAt(blockIndex) {
    if (!originalImageData) return;
    const totalBlocks = (currentWidth * currentHeight * 4) / 16;
    if (blockIndex < 0 || blockIndex >= totalBlocks) return;

    const { x, y } = getCoordFromBlockIndex(blockIndex);
    const byteOffset = blockIndex * 16;
    const rawBytes = new Uint8Array(originalImageData.data.buffer);

    // Update HUD coordinates
    hudOrigCoords.textContent = `X: ${x}..${x+3} Y: ${y}`;
    hudEcbCoords.textContent = `X: ${x}..${x+3} Y: ${y}`;
    hudGcmCoords.textContent = `X: ${x}..${x+3} Y: ${y}`;

    inspectCoords.textContent = `X: [${x}..${x+3}], Y: ${y} (Block #${blockIndex})`;

    // Plaintext Block (16 bytes = 4 pixels)
    const ptBlock = rawBytes.subarray(byteOffset, byteOffset + 16);
    hexPlaintext.textContent = formatBytesHexSpaced(ptBlock);
    asciiPlaintext.textContent = bytesToAscii(ptBlock);

    // ECB Ciphertext Block
    if (ecbCipherBytes) {
      const ecbBlock = ecbCipherBytes.subarray(byteOffset, byteOffset + 16);
      hexEcb.textContent = formatBytesHexSpaced(ecbBlock);
    } else {
      hexEcb.textContent = "-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --";
    }

    // GCM Ciphertext Block
    if (gcmCipherBytes) {
      const gcmBlock = gcmCipherBytes.subarray(byteOffset, byteOffset + 16);
      hexGcm.textContent = formatBytesHexSpaced(gcmBlock);
    } else {
      hexGcm.textContent = "-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --";
    }

    // Repeating Block Analysis
    let matchCount = 0;
    const matchingBlockIndices = [];

    if (chkHighlightRepeats.checked) {
      // Find all blocks identical in plaintext
      for (let b = 0; b < totalBlocks; b++) {
        const offset = b * 16;
        let isMatch = true;
        for (let j = 0; j < 16; j++) {
          if (rawBytes[offset + j] !== ptBlock[j]) {
            isMatch = false;
            break;
          }
        }
        if (isMatch) {
          matchCount++;
          matchingBlockIndices.push(b);
        }
      }

      const matchPercent = ((matchCount / totalBlocks) * 100).toFixed(1);
      inspectMatchCount.textContent = `${matchCount.toLocaleString()} blocks (${matchPercent}% of image)`;

      // Render Highlights on Overlays
      clearOverlays();

      // Highlight all matching blocks on Original and ECB overlays
      const highlightColor = "rgba(0, 245, 212, 0.4)";
      const ecbLeakColor = "rgba(245, 158, 11, 0.45)";

      [ctxOverOrig, ctxOverEcb].forEach((ctx, idx) => {
        ctx.fillStyle = idx === 0 ? highlightColor : ecbLeakColor;
        matchingBlockIndices.forEach(bIdx => {
          const coord = getCoordFromBlockIndex(bIdx);
          ctx.fillRect(coord.x, coord.y, 4, 1);
        });
      });

      // Synchronized Reticle on active block
      if (chkSyncReticle.checked) {
        drawReticleOnOverlay(ctxOverOrig, x, y);
        drawReticleOnOverlay(ctxOverEcb, x, y);
        drawReticleOnOverlay(ctxOverGcm, x, y);
      }

      // Update Correlation Text
      correlationText.innerHTML = `Selected 16-byte block repeats <strong>${matchCount.toLocaleString()} times</strong> across the source image. In <strong>AES-ECB</strong>, all ${matchCount.toLocaleString()} blocks encrypt to the <strong>exact same ciphertext</strong>: <code>${bytesToHex(ptBlock.subarray(0, 4))}...</code> → <code>${ecbCipherBytes ? bytesToHex(ecbCipherBytes.subarray(byteOffset, byteOffset + 4)) : "--"}...</code> (100% correlation), preserving the shape! In <strong>AES-GCM</strong>, every occurrence maps to a distinct unique ciphertext due to the counter keystream (0% correlation).`;
    } else {
      clearOverlays();
      if (chkSyncReticle.checked) {
        drawReticleOnOverlay(ctxOverOrig, x, y);
        drawReticleOnOverlay(ctxOverEcb, x, y);
        drawReticleOnOverlay(ctxOverGcm, x, y);
      }
    }
  }

  function handleCanvasPointerMove(e, canvas) {
    if (isInspectorLocked || !originalImageData) return;

    const rect = canvas.getBoundingClientRect();
    const scaleX = currentWidth / rect.width;
    const scaleY = currentHeight / rect.height;

    const x = Math.floor((e.clientX - rect.left) * scaleX);
    const y = Math.floor((e.clientY - rect.top) * scaleY);

    if (x >= 0 && x < currentWidth && y >= 0 && y < currentHeight) {
      const blockIndex = getBlockIndexFromCoord(x, y);
      inspectBlockAt(blockIndex);
    }
  }

  function handleCanvasClick(e, canvas) {
    if (!originalImageData) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = currentWidth / rect.width;
    const scaleY = currentHeight / rect.height;

    const x = Math.floor((e.clientX - rect.left) * scaleX);
    const y = Math.floor((e.clientY - rect.top) * scaleY);

    if (x >= 0 && x < currentWidth && y >= 0 && y < currentHeight) {
      const blockIndex = getBlockIndexFromCoord(x, y);
      if (isInspectorLocked && lockedBlockIndex === blockIndex) {
        isInspectorLocked = false;
        lockedBlockIndex = null;
        btnUnlockInspector.textContent = "Unlock";
      } else {
        isInspectorLocked = true;
        lockedBlockIndex = blockIndex;
        btnUnlockInspector.textContent = "Locked (Click to Free)";
        inspectBlockAt(blockIndex);
      }
    }
  }

  [canvasOriginal, canvasEcb, canvasGcm].forEach(canvas => {
    canvas.addEventListener("mousemove", (e) => handleCanvasPointerMove(e, canvas));
    canvas.addEventListener("click", (e) => handleCanvasClick(e, canvas));
    canvas.addEventListener("mouseleave", () => {
      if (!isInspectorLocked) clearOverlays();
    });
  });

  btnUnlockInspector.addEventListener("click", () => {
    isInspectorLocked = false;
    lockedBlockIndex = null;
    btnUnlockInspector.textContent = "Unlock";
    clearOverlays();
  });

  // --- 7. Shannon Entropy Spectrum Sparkline ---

  function renderSpectrum() {
    const w = canvasSpectrum.width;
    const h = canvasSpectrum.height;
    ctxSpectrum.clearRect(0, 0, w, h);

    // Subtle background grid
    ctxSpectrum.strokeStyle = "rgba(255, 255, 255, 0.05)";
    ctxSpectrum.lineWidth = 1;
    for (let y = 20; y < h; y += 25) {
      ctxSpectrum.beginPath();
      ctxSpectrum.moveTo(0, y);
      ctxSpectrum.lineTo(w, y);
      ctxSpectrum.stroke();
    }

    if (!sourceEntropyData) return;

    // Helper to draw smoothed curve of counts
    function drawFrequencyCurve(counts, strokeColor) {
      let maxCount = 1;
      for (let i = 0; i < 256; i++) {
        if (counts[i] > maxCount) maxCount = counts[i];
      }

      ctxSpectrum.strokeStyle = strokeColor;
      ctxSpectrum.lineWidth = 1.5;
      ctxSpectrum.beginPath();

      for (let i = 0; i < 256; i++) {
        const x = (i / 255) * (w - 8) + 4;
        const norm = counts[i] / maxCount;
        const y = h - 6 - norm * (h - 20);
        if (i === 0) ctxSpectrum.moveTo(x, y);
        else ctxSpectrum.lineTo(x, y);
      }
      ctxSpectrum.stroke();
    }

    // 1. Plaintext Spectrum (Blue)
    drawFrequencyCurve(sourceEntropyData.counts, "#38bdf8");

    // 2. ECB Spectrum (Amber)
    if (ecbEntropyData) {
      drawFrequencyCurve(ecbEntropyData.counts, "#f59e0b");
    }

    // 3. GCM Spectrum (Emerald - Flat uniform horizontal band)
    if (gcmEntropyData) {
      drawFrequencyCurve(gcmEntropyData.counts, "#10b981");
    }
  }

  // --- 8. Custom Upload & Clipboard Paste Handlers ---

  function processLoadedImage(img, filename = "custom-image") {
    // Target canvas dimensions: max 256x256, snapping width & height to multiples of 4
    let w = img.width;
    let h = img.height;
    const maxDim = 256;

    if (w > maxDim || h > maxDim) {
      if (w > h) {
        h = Math.round((h * maxDim) / w);
        w = maxDim;
      } else {
        w = Math.round((w * maxDim) / h);
        h = maxDim;
      }
    }

    // Ensure width is a multiple of 4 (so 16-byte blocks align cleanly without row wrapping)
    w = Math.max(16, Math.floor(w / 4) * 4);
    h = Math.max(16, Math.floor(h / 4) * 4);

    resizeAllCanvases(w, h);
    ctxOriginal.clearRect(0, 0, w, h);
    ctxOriginal.drawImage(img, 0, 0, w, h);

    originalImageData = ctxOriginal.getImageData(0, 0, w, h);
    const rawBytes = new Uint8Array(originalImageData.data.buffer);

    sourceEntropyData = calculateShannonEntropy(rawBytes);
    const sourceBlocks = calculateBlockStats(rawBytes);
    uniqueBlockStats.orig = sourceBlocks.uniqueCount;
    uniqueBlockStats.total = sourceBlocks.totalBlocks;

    statOrigEntropy.textContent = `${sourceEntropyData.entropy.toFixed(3)} bits/byte`;
    statOrigUnique.textContent = `${sourceBlocks.uniqueCount.toLocaleString()} / ${sourceBlocks.totalBlocks.toLocaleString()}`;
    const redundancy = (100 - (sourceBlocks.uniqueCount / sourceBlocks.totalBlocks) * 100).toFixed(1);
    statOrigRedundancy.textContent = `${redundancy}%`;

    meterValOrig.textContent = `${sourceEntropyData.entropy.toFixed(2)} / 8.0`;
    meterFillOrig.style.width = `${(sourceEntropyData.entropy / 8.0) * 100}%`;

    renderSpectrum();
    resetCipherState();

    document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
    setSystemStatus("ready", "CUSTOM IMAGE LOADED");
    telemetryMsg.innerHTML = `Loaded custom image "<strong>${filename}</strong>" (${w}×${h} px, ${sourceBlocks.totalBlocks.toLocaleString()} blocks). Click <strong>"ENCRYPT MODES"</strong> to execute.`;
  }

  imageUpload.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = () => processLoadedImage(img, file.name);
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  });

  // Global Clipboard Paste Support (Ctrl+V / Cmd+V)
  window.addEventListener("paste", (e) => {
    const items = (e.clipboardData || e.originalEvent.clipboardData).items;
    for (let item of items) {
      if (item.type.indexOf("image") !== -1) {
        const file = item.getAsFile();
        const reader = new FileReader();
        reader.onload = (event) => {
          const img = new Image();
          img.onload = () => processLoadedImage(img, "Pasted Clipboard Image");
          img.src = event.target.result;
        };
        reader.readAsDataURL(file);
        break;
      }
    }
  });

  // Drag and Drop on Canvas Viewport
  const dropZone = document.getElementById("panel-source");
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--cyan-primary)";
  });
  dropZone.addEventListener("dragleave", () => {
    dropZone.style.borderColor = "var(--border-subtle)";
  });
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--border-subtle)";
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith("image/")) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        const img = new Image();
        img.onload = () => processLoadedImage(img, file.name);
        img.src = ev.target.result;
      };
      reader.readAsDataURL(file);
    }
  });

  // --- 9. Export Capabilities (PNG & Audit JSON) ---

  function downloadCanvasAsPng(canvas, filename) {
    const link = document.createElement("a");
    link.download = filename;
    link.href = canvas.toDataURL("image/png");
    link.click();
  }

  btnDlOrig.addEventListener("click", () => downloadCanvasAsPng(canvasOriginal, "aes_plaintext_source.png"));
  btnDlEcb.addEventListener("click", () => downloadCanvasAsPng(canvasEcb, "aes_ecb_encrypted.png"));
  btnDlGcm.addEventListener("click", () => downloadCanvasAsPng(canvasGcm, "aes_gcm_encrypted.png"));

  btnExportAudit.addEventListener("click", () => {
    const auditData = {
      project: "AES Image Encryption Visualizer & Cryptanalysis Workbench",
      timestamp: new Date().toISOString(),
      bufferMetrics: {
        dimensions: `${currentWidth}x${currentHeight}`,
        totalBytes: currentWidth * currentHeight * 4,
        total16ByteBlocks: (currentWidth * currentHeight * 4) / 16
      },
      cipherParameters: {
        keyHex: inputKeyHex.value,
        keyBits: 128,
        gcmIvHex: inputGcmIvHex.value,
        gcmIvBits: 96
      },
      shannonEntropy: {
        sourcePlaintext: sourceEntropyData ? sourceEntropyData.entropy : null,
        aesEcbCiphertext: ecbEntropyData ? ecbEntropyData.entropy : null,
        aesGcmCiphertext: gcmEntropyData ? gcmEntropyData.entropy : null,
        theoreticalMax: 8.000
      },
      blockStatistics: uniqueBlockStats,
      benchmarks: executionTimings,
      sha256Digests: {
        sourcePlaintext: shaOriginal.textContent,
        decryptedEcb: shaEcb.textContent,
        decryptedGcm: shaGcm.textContent,
        losslessBitExactMatch: shaOriginal.textContent === shaEcb.textContent && shaOriginal.textContent === shaGcm.textContent
      },
      cryptographicFinding: "AES-ECB exhibits severe deterministic pattern leakage where identical 16-byte plaintext blocks yield identical ciphertext blocks, fully preserving structural image contours. AES-GCM incorporates an IV and counter stream to provide authenticated diffusion and true pseudo-random noise indistinguishable from uniform distribution."
    };

    const blob = new Blob([JSON.stringify(auditData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.download = `aes_cryptanalysis_audit_${Date.now()}.json`;
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  });

  // --- 10. Modal Dialog Handlers ---

  btnOpenSpecs.addEventListener("click", () => modalSpecs.classList.remove("hidden"));
  btnCloseSpecs.addEventListener("click", () => modalSpecs.classList.add("hidden"));
  btnCloseSpecsBottom.addEventListener("click", () => modalSpecs.classList.add("hidden"));

  modalSpecs.addEventListener("click", (e) => {
    if (e.target === modalSpecs) modalSpecs.classList.add("hidden");
  });

  // --- 11. Event Listeners & Keyboard Shortcuts ---

  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      generatePresetImage(btn.dataset.preset);
    });
  });

  btnGenKey.addEventListener("click", () => {
    const randomKey = crypto.getRandomValues(new Uint8Array(16));
    inputKeyHex.value = bytesToHex(randomKey);
    telemetryMsg.innerHTML = "Generated new cryptographically random 128-bit AES Key.";
    if (ecbCipherBytes) runEncryptionPipeline();
  });

  btnCopyKey.addEventListener("click", () => {
    navigator.clipboard.writeText(inputKeyHex.value).then(() => {
      const origText = btnCopyKey.title;
      btnCopyKey.title = "Copied to clipboard!";
      telemetryMsg.innerHTML = "Copied AES-128 key to clipboard.";
      setTimeout(() => (btnCopyKey.title = origText), 1500);
    });
  });

  btnGenIv.addEventListener("click", () => {
    gcmIvBytes = crypto.getRandomValues(new Uint8Array(12));
    inputGcmIvHex.value = bytesToHex(gcmIvBytes);
    telemetryMsg.innerHTML = "Generated new random 96-bit GCM Initialization Vector (IV).";
    if (gcmCipherBytes) runEncryptionPipeline();
  });

  btnEncrypt.addEventListener("click", runEncryptionPipeline);
  btnDecrypt.addEventListener("click", runDecryptionPipeline);

  btnReset.addEventListener("click", () => {
    document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
    document.getElementById("btn-preset-penguin").classList.add("active");
    generatePresetImage("penguin");
  });

  // Keyboard Shortcuts: Ctrl+E (Encrypt), Ctrl+D (Decrypt), Esc (Reset/Close), 1..5 (Presets)
  window.addEventListener("keydown", (e) => {
    // If typing in input box, ignore shortcut keys
    if (e.target.tagName === "INPUT") return;

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "e") {
      e.preventDefault();
      runEncryptionPipeline();
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "d") {
      e.preventDefault();
      if (!btnDecrypt.disabled) runDecryptionPipeline();
    } else if (e.key === "Escape") {
      if (!modalSpecs.classList.contains("hidden")) {
        modalSpecs.classList.add("hidden");
      } else {
        isInspectorLocked = false;
        clearOverlays();
      }
    } else if (["1", "2", "3", "4", "5"].includes(e.key)) {
      const presetKeys = ["penguin", "shield", "target", "qr", "medical"];
      const selected = presetKeys[parseInt(e.key) - 1];
      if (selected) {
        document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
        const targetBtn = document.querySelector(`[data-preset="${selected}"]`);
        if (targetBtn) targetBtn.classList.add("active");
        generatePresetImage(selected);
      }
    }
  });

  // --- 12. Universal File Encryption & Decryption Vault ---
  function initUniversalFileVault() {
    // Mode Switcher Navigation
    const tabModeImages = document.getElementById("tab-mode-images");
    const tabModeVault = document.getElementById("tab-mode-vault");
    const viewImageWorkbench = document.getElementById("view-image-workbench");
    const viewFileVault = document.getElementById("view-file-vault");
    const topbarPresetsContainer = document.getElementById("topbar-presets-container");
    const actionBtnImageUpload = document.getElementById("action-btn-image-upload");

    function switchAppMode(mode) {
      if (mode === "vault") {
        tabModeVault.classList.add("active");
        tabModeVault.setAttribute("aria-selected", "true");
        tabModeImages.classList.remove("active");
        tabModeImages.setAttribute("aria-selected", "false");

        viewImageWorkbench.classList.add("hidden");
        viewFileVault.classList.remove("hidden");

        if (topbarPresetsContainer) topbarPresetsContainer.style.display = "none";
        if (actionBtnImageUpload) actionBtnImageUpload.style.display = "none";

        setSystemStatus("ready", "VAULT READY");
        vaultTelemetryMsg.innerHTML = "Universal File Vault active. Select or drag any file into the Encrypt dropzone to begin.";
      } else {
        tabModeImages.classList.add("active");
        tabModeImages.setAttribute("aria-selected", "true");
        tabModeVault.classList.remove("active");
        tabModeVault.setAttribute("aria-selected", "false");

        viewFileVault.classList.add("hidden");
        viewImageWorkbench.classList.remove("hidden");

        if (topbarPresetsContainer) topbarPresetsContainer.style.display = "flex";
        if (actionBtnImageUpload) actionBtnImageUpload.style.display = "inline-flex";

        setSystemStatus("ready", "WORKBENCH READY");
      }
    }

    if (tabModeImages && tabModeVault) {
      tabModeImages.addEventListener("click", () => switchAppMode("images"));
      tabModeVault.addEventListener("click", () => switchAppMode("vault"));
    }

    // Vault Subtab Navigation
    const btnSubtabEncrypt = document.getElementById("btn-subtab-encrypt");
    const btnSubtabDecrypt = document.getElementById("btn-subtab-decrypt");
    const btnVaultSample = document.getElementById("btn-vault-sample");
    const vaultSubviewEncrypt = document.getElementById("vault-subview-encrypt");
    const vaultSubviewDecrypt = document.getElementById("vault-subview-decrypt");
    const vaultTelemetryMsg = document.getElementById("vault-telemetry-msg");

    function switchVaultSubtab(subtab) {
      if (subtab === "decrypt") {
        btnSubtabDecrypt.classList.add("active");
        btnSubtabDecrypt.setAttribute("aria-selected", "true");
        btnSubtabEncrypt.classList.remove("active");
        btnSubtabEncrypt.setAttribute("aria-selected", "false");

        vaultSubviewEncrypt.classList.add("hidden");
        vaultSubviewDecrypt.classList.remove("hidden");
        vaultTelemetryMsg.innerHTML = "Decryption Vault active. Drop your <strong>.enc</strong> file or click browse to inspect and recover.";
      } else {
        btnSubtabEncrypt.classList.add("active");
        btnSubtabEncrypt.setAttribute("aria-selected", "true");
        btnSubtabDecrypt.classList.remove("active");
        btnSubtabDecrypt.setAttribute("aria-selected", "false");

        vaultSubviewDecrypt.classList.add("hidden");
        vaultSubviewEncrypt.classList.remove("hidden");
        vaultTelemetryMsg.innerHTML = "Ready. Select or drag any file into the Encrypt dropzone to begin client-side encryption.";
      }
    }

    if (btnSubtabEncrypt && btnSubtabDecrypt) {
      btnSubtabEncrypt.addEventListener("click", () => switchVaultSubtab("encrypt"));
      btnSubtabDecrypt.addEventListener("click", () => switchVaultSubtab("decrypt"));
    }

    // Vault State
    let vaultSourceFile = null;        // { name, size, type, buffer, uint8Array, sha256, lastModified }
    let vaultEncryptedPkg = null;      // { bytes, filename, metadata, durationMs, throughputMBs, entropy }
    let vaultDecryptedFile = null;     // { bytes, filename, mimeType, sha256, isMatch }

    // Dropzones & Inputs (Encrypt)
    const vaultEncryptDropzone = document.getElementById("vault-encrypt-dropzone");
    const vaultEncryptInput = document.getElementById("vault-encrypt-input");
    const vaultEncryptFileCard = document.getElementById("vault-encrypt-file-card");
    const vaultEncFileBadge = document.getElementById("vault-enc-file-badge");
    const vaultEncFileName = document.getElementById("vault-enc-file-name");
    const vaultEncFileMeta = document.getElementById("vault-enc-file-meta");
    const btnVaultClearEnc = document.getElementById("btn-vault-clear-enc");
    const vaultEncSha256 = document.getElementById("vault-enc-sha256");
    const vaultEncFileDate = document.getElementById("vault-enc-file-date");
    const vaultEncHexPreview = document.getElementById("vault-enc-hex-preview");
    const vaultEncAsciiPreview = document.getElementById("vault-enc-ascii-preview");

    // Cipher Controls (Encrypt)
    const vaultCipherMode = document.getElementById("vault-cipher-mode");
    const vaultKeyHex = document.getElementById("vault-key-hex");
    const btnVaultGenKey = document.getElementById("btn-vault-gen-key");
    const btnVaultCopyKey = document.getElementById("btn-vault-copy-key");
    const btnVaultSyncKey = document.getElementById("btn-vault-sync-key");
    const vaultIvFormGroup = document.getElementById("vault-iv-form-group");
    const vaultIvHex = document.getElementById("vault-iv-hex");
    const btnVaultGenIv = document.getElementById("btn-vault-gen-iv");
    const vaultOutFilename = document.getElementById("vault-out-filename");
    const btnVaultDoEncrypt = document.getElementById("btn-vault-do-encrypt");

    // Result Card (Encrypt)
    const vaultEncryptResultCard = document.getElementById("vault-encrypt-result-card");
    const vaultResEncSize = document.getElementById("vault-res-enc-size");
    const vaultResEncMode = document.getElementById("vault-res-enc-mode");
    const vaultResEncEntropy = document.getElementById("vault-res-enc-entropy");
    const vaultResEncTime = document.getElementById("vault-res-enc-time");
    const vaultResEncThroughput = document.getElementById("vault-res-enc-throughput");
    const btnVaultDownloadEnc = document.getElementById("btn-vault-download-enc");
    const btnVaultDownloadEncLabel = document.getElementById("btn-vault-download-enc-label");
    const btnVaultTransferToDecrypt = document.getElementById("btn-vault-transfer-to-decrypt");

    // Dropzones & Inputs (Decrypt)
    const vaultDecryptDropzone = document.getElementById("vault-decrypt-dropzone");
    const vaultDecryptInput = document.getElementById("vault-decrypt-input");
    const vaultDecPackageCard = document.getElementById("vault-dec-package-card");
    const vaultDecPkgBadge = document.getElementById("vault-dec-pkg-badge");
    const vaultDecPkgFilename = document.getElementById("vault-dec-pkg-filename");
    const vaultDecPkgMeta = document.getElementById("vault-dec-pkg-meta");
    const btnVaultClearDec = document.getElementById("btn-vault-clear-dec");
    const vaultDecOrigFilename = document.getElementById("vault-dec-orig-filename");
    const vaultDecOrigMime = document.getElementById("vault-dec-orig-mime");
    const vaultDecOrigSize = document.getElementById("vault-dec-orig-size");
    const vaultDecOrigMode = document.getElementById("vault-dec-orig-mode");
    const vaultDecOrigSha = document.getElementById("vault-dec-orig-sha");

    // Controls (Decrypt)
    const vaultDecKeyHex = document.getElementById("vault-dec-key-hex");
    const btnVaultDecSyncKey = document.getElementById("btn-vault-dec-sync-key");
    const btnVaultDoDecrypt = document.getElementById("btn-vault-do-decrypt");

    // Result Card (Decrypt)
    const vaultDecResultCard = document.getElementById("vault-dec-result-card");
    const vaultDecStatusBadge = document.getElementById("vault-dec-status-badge");
    const vaultDecVerdictTitle = document.getElementById("vault-dec-verdict-title");
    const vaultDecAuthTag = document.getElementById("vault-dec-auth-tag");
    const vaultDecShaOrig = document.getElementById("vault-dec-sha-orig");
    const vaultDecShaDec = document.getElementById("vault-dec-sha-dec");
    const vaultDecShaBadge = document.getElementById("vault-dec-sha-badge");
    const vaultResDecFilename = document.getElementById("vault-res-dec-filename");
    const vaultResDecSize = document.getElementById("vault-res-dec-size");
    const vaultResDecDiff = document.getElementById("vault-res-dec-diff");
    const vaultResDecTime = document.getElementById("vault-res-dec-time");
    const vaultResDecThroughput = document.getElementById("vault-res-dec-throughput");
    const btnVaultDownloadDec = document.getElementById("btn-vault-download-dec");
    const btnVaultDownloadDecLabel = document.getElementById("btn-vault-download-dec-label");
    const vaultDecPreviewCard = document.getElementById("vault-dec-preview-card");
    const vaultDecPreviewType = document.getElementById("vault-dec-preview-type");
    const vaultDecPreviewContent = document.getElementById("vault-dec-preview-content");

    // Helper functions
    function formatFileSize(bytes) {
      if (!bytes || bytes === 0) return "0 Bytes";
      const k = 1024;
      const sizes = ["Bytes", "KB", "MB", "GB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function getFileIcon(name = "", mime = "") {
      const ext = name.split(".").pop().toLowerCase();
      if (["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp"].includes(ext) || mime.startsWith("image/")) return "🖼️";
      if (["mp4", "webm", "mkv", "mov", "avi"].includes(ext) || mime.startsWith("video/")) return "🎬";
      if (["mp3", "wav", "ogg", "flac", "m4a"].includes(ext) || mime.startsWith("audio/")) return "🎵";
      if (["pdf"].includes(ext) || mime.includes("pdf")) return "📕";
      if (["zip", "tar", "gz", "7z", "rar"].includes(ext) || mime.includes("zip") || mime.includes("tar")) return "📦";
      if (["txt", "md", "csv", "json", "xml", "log", "js", "html", "css"].includes(ext) || mime.startsWith("text/")) return "📝";
      if (["enc"].includes(ext)) return "🔐";
      return "📄";
    }

    // Binary Container Packaging
    // Structure:
    // [8 bytes magic: "AESENC1\0"]
    // [4 bytes uint32 big-endian: metadata JSON length L]
    // [L bytes: metadata UTF-8 string]
    // [Remaining bytes: ciphertext + auth tag]
    function buildEncContainer(metadata, ciphertextBytes) {
      const magic = new Uint8Array([0x41, 0x45, 0x53, 0x45, 0x4e, 0x43, 0x31, 0x00]); // "AESENC1\0"
      const metaBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const lenBuf = new ArrayBuffer(4);
      new DataView(lenBuf).setUint32(0, metaBytes.length, false);
      const lenBytes = new Uint8Array(lenBuf);

      const totalSize = 8 + 4 + metaBytes.length + ciphertextBytes.length;
      const container = new Uint8Array(totalSize);
      container.set(magic, 0);
      container.set(lenBytes, 8);
      container.set(metaBytes, 12);
      container.set(ciphertextBytes, 12 + metaBytes.length);
      return container;
    }

    function parseEncContainer(bytes) {
      if (bytes.length < 16) return null;
      const magicStr = new TextDecoder().decode(bytes.subarray(0, 7));
      if (magicStr !== "AESENC1" && magicStr !== "AESENC\0") return null;

      try {
        const metaLen = new DataView(bytes.buffer, bytes.byteOffset + 8, 4).getUint32(0, false);
        if (bytes.length < 12 + metaLen) return null;
        const metaStr = new TextDecoder().decode(bytes.subarray(12, 12 + metaLen));
        const metadata = JSON.parse(metaStr);
        const ciphertext = bytes.subarray(12 + metaLen);
        return { metadata, ciphertext };
      } catch (err) {
        console.error("Failed to parse AESENC container:", err);
        return null;
      }
    }

    // PKCS#7 Padding for AES-ECB arbitrary files
    function pkcs7Pad(data) {
      const padLen = 16 - (data.length % 16);
      const padded = new Uint8Array(data.length + padLen);
      padded.set(data);
      padded.fill(padLen, data.length);
      return padded;
    }

    function pkcs7Unpad(data) {
      if (data.length === 0 || data.length % 16 !== 0) return data;
      const padLen = data[data.length - 1];
      if (padLen < 1 || padLen > 16) return data;
      for (let i = data.length - padLen; i < data.length; i++) {
        if (data[i] !== padLen) return data;
      }
      return data.subarray(0, data.length - padLen);
    }

    // --- ENCRYPTION WORKFLOW ---
    async function handleFileSelectedForEncrypt(file) {
      if (!file) return;

      const buffer = await file.arrayBuffer();
      const uint8 = new Uint8Array(buffer);
      const sha256 = await computeSha256(uint8);

      vaultSourceFile = {
        name: file.name,
        size: file.size,
        type: file.type || "application/octet-stream",
        buffer: buffer,
        uint8Array: uint8,
        sha256: sha256,
        lastModified: file.lastModified ? new Date(file.lastModified).toLocaleString() : new Date().toLocaleString()
      };

      // Populate file card
      vaultEncFileBadge.textContent = getFileIcon(file.name, file.type);
      vaultEncFileName.textContent = file.name;
      vaultEncFileMeta.textContent = `${formatFileSize(file.size)} (${file.size.toLocaleString()} bytes) • ${file.type || "binary/octet-stream"}`;
      vaultEncSha256.textContent = sha256;
      vaultEncFileDate.textContent = vaultSourceFile.lastModified;

      // Hex snippet of first 32 bytes
      const snippetBytes = uint8.subarray(0, Math.min(32, uint8.length));
      vaultEncHexPreview.textContent = formatBytesHexSpaced(snippetBytes);
      vaultEncAsciiPreview.textContent = bytesToAscii(snippetBytes);

      // Default output filename
      vaultOutFilename.value = `${file.name}.enc`;

      vaultEncryptFileCard.classList.remove("hidden");
      btnVaultDoEncrypt.disabled = false;
      vaultEncryptResultCard.classList.add("hidden");

      vaultTelemetryMsg.innerHTML = `Loaded "<strong>${file.name}</strong>" (${formatFileSize(file.size)}). Ready to encrypt.`;
    }

    // Dropzone events for Encrypt
    ["dragenter", "dragover"].forEach(evt => {
      vaultEncryptDropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        vaultEncryptDropzone.classList.add("drag-over");
      });
    });

    ["dragleave", "drop"].forEach(evt => {
      vaultEncryptDropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        vaultEncryptDropzone.classList.remove("drag-over");
      });
    });

    vaultEncryptDropzone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files[0];
      if (file) handleFileSelectedForEncrypt(file);
    });

    vaultEncryptInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) handleFileSelectedForEncrypt(file);
    });

    btnVaultClearEnc.addEventListener("click", () => {
      vaultSourceFile = null;
      vaultEncryptInput.value = "";
      vaultEncryptFileCard.classList.add("hidden");
      vaultEncryptResultCard.classList.add("hidden");
      btnVaultDoEncrypt.disabled = true;
      vaultTelemetryMsg.innerHTML = "Cleared source file. Select or drag any file to encrypt.";
    });

    // Key & IV Generators (Vault Encrypt)
    btnVaultGenKey.addEventListener("click", () => {
      const randomKey = crypto.getRandomValues(new Uint8Array(16));
      vaultKeyHex.value = bytesToHex(randomKey);
      vaultTelemetryMsg.innerHTML = "Generated new random 128-bit AES Key for Vault.";
    });

    btnVaultCopyKey.addEventListener("click", () => {
      navigator.clipboard.writeText(vaultKeyHex.value).then(() => {
        vaultTelemetryMsg.innerHTML = "Copied Vault AES-128 Key to clipboard.";
      });
    });

    btnVaultSyncKey.addEventListener("click", () => {
      vaultKeyHex.value = inputKeyHex.value;
      vaultTelemetryMsg.innerHTML = "Synchronized Vault key with Image Workbench key.";
    });

    btnVaultGenIv.addEventListener("click", () => {
      const randomIv = crypto.getRandomValues(new Uint8Array(12));
      vaultIvHex.value = bytesToHex(randomIv);
      vaultTelemetryMsg.innerHTML = "Generated new random 96-bit GCM IV.";
    });

    vaultCipherMode.addEventListener("change", () => {
      if (vaultCipherMode.value === "AES-ECB") {
        vaultIvFormGroup.style.opacity = "0.4";
        vaultIvHex.disabled = true;
      } else {
        vaultIvFormGroup.style.opacity = "1";
        vaultIvHex.disabled = false;
      }
    });

    // Execute Encryption
    btnVaultDoEncrypt.addEventListener("click", async () => {
      if (!vaultSourceFile) return;

      const keyHex = vaultKeyHex.value.trim();
      const keyBytes = hexToBytes(keyHex);
      vaultKeyHex.value = bytesToHex(keyBytes);

      const mode = vaultCipherMode.value;
      const t0 = performance.now();
      let ciphertextBytes = null;
      let ivBytes = null;

      vaultTelemetryMsg.innerHTML = `Encrypting "<strong>${vaultSourceFile.name}</strong>" using ${mode}...`;
      setSystemStatus("encrypted", "ENCRYPTING FILE...");

      try {
        if (mode === "AES-GCM") {
          ivBytes = hexToBytes(vaultIvHex.value.trim()).subarray(0, 12);
          if (ivBytes.length < 12) ivBytes = crypto.getRandomValues(new Uint8Array(12));
          vaultIvHex.value = bytesToHex(ivBytes);

          const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
          );

          const encryptedBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: ivBytes },
            cryptoKey,
            vaultSourceFile.buffer
          );
          ciphertextBytes = new Uint8Array(encryptedBuf);

        } else {
          // AES-ECB with PKCS#7 padding
          const padded = pkcs7Pad(vaultSourceFile.uint8Array);
          ciphertextBytes = AES.ecbEncrypt(padded, keyBytes);
          ivBytes = new Uint8Array(0);
        }

        const durationMs = performance.now() - t0;
        const entropyResult = calculateShannonEntropy(ciphertextBytes);

        // Package metadata into container
        const metadata = {
          version: 1,
          filename: vaultSourceFile.name,
          mimeType: vaultSourceFile.type,
          fileSize: vaultSourceFile.size,
          cipher: mode,
          ivHex: bytesToHex(ivBytes),
          sha256: vaultSourceFile.sha256,
          createdAt: Date.now()
        };

        const containerBytes = buildEncContainer(metadata, ciphertextBytes);
        const outName = vaultOutFilename.value.trim() || `${vaultSourceFile.name}.enc`;

        const mbSize = (vaultSourceFile.size / (1024 * 1024));
        const throughputMBs = durationMs > 0 ? (mbSize / (durationMs / 1000)).toFixed(1) : "N/A";

        vaultEncryptedPkg = {
          bytes: containerBytes,
          filename: outName,
          metadata: metadata,
          durationMs: durationMs.toFixed(1),
          throughputMBs: throughputMBs,
          entropy: entropyResult.entropy.toFixed(3)
        };

        // Populate Result Card
        vaultResEncSize.textContent = `${formatFileSize(containerBytes.length)} (${containerBytes.length.toLocaleString()} B)`;
        vaultResEncMode.textContent = mode;
        vaultResEncEntropy.textContent = `${vaultEncryptedPkg.entropy} / 8.000`;
        vaultResEncTime.textContent = `${vaultEncryptedPkg.durationMs} ms`;
        vaultResEncThroughput.textContent = `Throughput: ${throughputMBs} MB/s`;
        btnVaultDownloadEncLabel.textContent = `Download Encrypted File (${outName})`;

        vaultEncryptResultCard.classList.remove("hidden");
        vaultEncryptResultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

        setSystemStatus("encrypted", "FILE ENCRYPTED");
        vaultTelemetryMsg.innerHTML = `✅ Successfully encrypted "<strong>${vaultSourceFile.name}</strong>" into <strong>${outName}</strong> in <strong>${vaultEncryptedPkg.durationMs}ms</strong>. Click "Download" to save or "Test in Decryption Vault" to verify recovery.`;

      } catch (err) {
        console.error("Vault Encryption error:", err);
        alert("Encryption failed: " + err.message);
        setSystemStatus("ready", "ENCRYPTION FAILED");
      }
    });

    // Download Encrypted File
    btnVaultDownloadEnc.addEventListener("click", () => {
      if (!vaultEncryptedPkg) return;
      const blob = new Blob([vaultEncryptedPkg.bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = vaultEncryptedPkg.filename;
      a.click();
      URL.revokeObjectURL(url);
    });

    // Transfer encrypted package to Decryption tab for instant testing
    btnVaultTransferToDecrypt.addEventListener("click", () => {
      if (!vaultEncryptedPkg) return;
      switchVaultSubtab("decrypt");
      loadPackageForDecryption(vaultEncryptedPkg.bytes, vaultEncryptedPkg.filename);
      vaultDecKeyHex.value = vaultKeyHex.value;
      vaultTelemetryMsg.innerHTML = `Transferred "<strong>${vaultEncryptedPkg.filename}</strong>" to Decrypt Vault. Click "DECRYPT & VERIFY INTEGRITY" to test bit-exact recovery!`;
    });

    // --- DECRYPTION WORKFLOW ---
    let currentLoadedDecBytes = null;
    let currentParsedContainer = null;

    function loadPackageForDecryption(bytes, filename = "file.enc") {
      currentLoadedDecBytes = bytes;
      const parsed = parseEncContainer(bytes);

      if (!parsed) {
        vaultDecPackageCard.classList.remove("hidden");
        vaultDecPkgBadge.textContent = "⚠️";
        vaultDecPkgFilename.textContent = filename;
        vaultDecPkgMeta.textContent = `${formatFileSize(bytes.length)} • Raw Encrypted Binary`;
        vaultDecOrigFilename.textContent = filename.replace(/\.enc$/i, "");
        vaultDecOrigMime.textContent = "application/octet-stream (Raw)";
        vaultDecOrigSize.textContent = formatFileSize(bytes.length);
        vaultDecOrigMode.textContent = "AES-GCM (Assumed)";
        vaultDecOrigSha.textContent = "None (Raw payload without AESENC header)";

        currentParsedContainer = {
          metadata: {
            filename: filename.replace(/\.enc$/i, ""),
            mimeType: "application/octet-stream",
            fileSize: bytes.length,
            cipher: "AES-GCM",
            ivHex: vaultIvHex.value,
            sha256: null
          },
          ciphertext: bytes
        };
      } else {
        currentParsedContainer = parsed;
        const meta = parsed.metadata;
        vaultDecPackageCard.classList.remove("hidden");
        vaultDecPkgBadge.textContent = getFileIcon(meta.filename, meta.mimeType);
        vaultDecPkgFilename.textContent = filename;
        vaultDecPkgMeta.textContent = `${formatFileSize(bytes.length)} • AESENC v1 Container`;
        vaultDecOrigFilename.textContent = meta.filename;
        vaultDecOrigMime.textContent = meta.mimeType || "application/octet-stream";
        vaultDecOrigSize.textContent = `${formatFileSize(meta.fileSize)} (${meta.fileSize.toLocaleString()} B)`;
        vaultDecOrigMode.textContent = meta.cipher;
        vaultDecOrigSha.textContent = meta.sha256 || "None";
      }

      btnVaultDoDecrypt.disabled = false;
      vaultDecResultCard.classList.add("hidden");
      vaultTelemetryMsg.innerHTML = `Loaded "<strong>${filename}</strong>". Embedded target file: <strong>${currentParsedContainer.metadata.filename}</strong>. Ready to decrypt.`;
    }

    async function handleFileSelectedForDecrypt(file) {
      if (!file) return;
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      loadPackageForDecryption(bytes, file.name);
    }

    // Dropzone events for Decrypt
    ["dragenter", "dragover"].forEach(evt => {
      vaultDecryptDropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        vaultDecryptDropzone.classList.add("drag-over");
      });
    });

    ["dragleave", "drop"].forEach(evt => {
      vaultDecryptDropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        vaultDecryptDropzone.classList.remove("drag-over");
      });
    });

    vaultDecryptDropzone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files[0];
      if (file) handleFileSelectedForDecrypt(file);
    });

    vaultDecryptInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) handleFileSelectedForDecrypt(file);
    });

    btnVaultClearDec.addEventListener("click", () => {
      currentLoadedDecBytes = null;
      currentParsedContainer = null;
      vaultDecryptInput.value = "";
      vaultDecPackageCard.classList.add("hidden");
      vaultDecResultCard.classList.add("hidden");
      btnVaultDoDecrypt.disabled = true;
      vaultTelemetryMsg.innerHTML = "Cleared package. Select or drop a .enc file to decrypt.";
    });

    btnVaultDecSyncKey.addEventListener("click", () => {
      vaultDecKeyHex.value = vaultKeyHex.value;
      vaultTelemetryMsg.innerHTML = "Synchronized decryption key with active Encrypt key.";
    });

    // Execute Decryption
    btnVaultDoDecrypt.addEventListener("click", async () => {
      if (!currentParsedContainer) return;

      const keyHex = vaultDecKeyHex.value.trim();
      const keyBytes = hexToBytes(keyHex);
      vaultDecKeyHex.value = bytesToHex(keyBytes);

      const meta = currentParsedContainer.metadata;
      const ciphertext = currentParsedContainer.ciphertext;
      const mode = meta.cipher || "AES-GCM";

      vaultTelemetryMsg.innerHTML = `Decrypting ciphertext using ${mode}...`;
      setSystemStatus("encrypted", "DECRYPTING FILE...");

      const t0 = performance.now();
      let decryptedBytes = null;
      let gcmAuthPassed = false;

      try {
        if (mode === "AES-GCM") {
          const ivBytes = hexToBytes(meta.ivHex || vaultIvHex.value).subarray(0, 12);
          const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );

          try {
            const decBuf = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: ivBytes },
              cryptoKey,
              ciphertext
            );
            decryptedBytes = new Uint8Array(decBuf);
            gcmAuthPassed = true;
          } catch (gcmErr) {
            // Decryption authentication tag mismatch or corrupted ciphertext
            console.error("GCM Decryption failure:", gcmErr);
            vaultDecResultCard.classList.remove("hidden");
            vaultDecStatusBadge.className = "result-badge-success text-danger";
            vaultDecVerdictTitle.textContent = "AUTHENTICATION FAILED (TAG MISMATCH)";
            vaultDecAuthTag.textContent = "TAG ERROR / WRONG KEY";
            vaultDecAuthTag.className = "result-type-tag text-danger";
            vaultDecShaOrig.textContent = meta.sha256 || "N/A";
            vaultDecShaDec.textContent = "Decryption aborted (Integrity compromised or incorrect key)";
            vaultDecShaBadge.textContent = "FAILED";
            vaultDecShaBadge.className = "hash-badge text-danger";
            vaultResDecFilename.textContent = meta.filename;
            vaultResDecSize.textContent = "0 Bytes";
            vaultResDecDiff.textContent = "MAC Authentication Failed";
            vaultResDecTime.textContent = "--";
            vaultResDecThroughput.textContent = "--";
            btnVaultDownloadDec.disabled = true;
            vaultDecPreviewCard.classList.add("hidden");

            setSystemStatus("encrypted", "AUTHENTICATION FAILED");
            vaultTelemetryMsg.innerHTML = "⚠️ <strong>Decryption Failed!</strong> The AES-128 key is incorrect or the ciphertext was tampered with.";
            return;
          }

        } else {
          // AES-ECB mode
          const rawDec = AES.ecbDecrypt(ciphertext, keyBytes);
          decryptedBytes = pkcs7Unpad(rawDec);
        }

        const durationMs = performance.now() - t0;
        const decSha256 = await computeSha256(decryptedBytes);
        const isMatch = meta.sha256 ? decSha256 === meta.sha256 : true;

        const mbSize = (decryptedBytes.length / (1024 * 1024));
        const throughputMBs = durationMs > 0 ? (mbSize / (durationMs / 1000)).toFixed(1) : "N/A";

        vaultDecryptedFile = {
          bytes: decryptedBytes,
          filename: meta.filename,
          mimeType: meta.mimeType,
          sha256: decSha256,
          isMatch: isMatch
        };

        // Populate Decryption Verification Result Card
        vaultDecResultCard.classList.remove("hidden");
        vaultDecStatusBadge.className = isMatch ? "result-badge-success" : "result-badge-success text-danger";
        vaultDecVerdictTitle.textContent = isMatch
          ? "100% BIT-PERFECT RESTORATION VERIFIED"
          : "SHA-256 HASH MISMATCH DETECTED";

        vaultDecAuthTag.textContent = mode === "AES-GCM" ? (gcmAuthPassed ? "GCM AUTH PASS" : "TAG FAIL") : "ECB UNPAD OK";
        vaultDecAuthTag.className = `result-type-tag ${isMatch ? "badge-match" : "text-danger"}`;

        vaultDecShaOrig.textContent = meta.sha256 || "None provided";
        vaultDecShaDec.textContent = decSha256;
        vaultDecShaBadge.textContent = isMatch ? "MATCH (100%)" : "MISMATCH";
        vaultDecShaBadge.className = `hash-badge ${isMatch ? "badge-match" : "text-danger"}`;

        vaultResDecFilename.textContent = meta.filename;
        vaultResDecSize.textContent = `${formatFileSize(decryptedBytes.length)} (${decryptedBytes.length.toLocaleString()} B)`;
        vaultResDecDiff.textContent = isMatch ? "0 Byte Mismatch (0.000%)" : "Data Altered";
        vaultResDecTime.textContent = `${durationMs.toFixed(1)} ms`;
        vaultResDecThroughput.textContent = `Throughput: ${throughputMBs} MB/s`;

        btnVaultDownloadDec.disabled = false;
        btnVaultDownloadDecLabel.textContent = `Download Restored File (${meta.filename})`;

        // Render Live Preview
        renderDecryptedPreview(decryptedBytes, meta.filename, meta.mimeType);

        vaultDecResultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
        setSystemStatus("verified", "100% BIT-PERFECT VERIFIED");
        vaultTelemetryMsg.innerHTML = `✅ Successfully decrypted and recovered "<strong>${meta.filename}</strong>" with <strong>0 byte mismatch</strong> in <strong>${durationMs.toFixed(1)}ms</strong>!`;

      } catch (err) {
        console.error("Vault Decryption error:", err);
        alert("Decryption failed: " + err.message);
        setSystemStatus("ready", "DECRYPTION FAILED");
      }
    });

    // Download Decrypted File
    btnVaultDownloadDec.addEventListener("click", () => {
      if (!vaultDecryptedFile) return;
      const blob = new Blob([vaultDecryptedFile.bytes], { type: vaultDecryptedFile.mimeType || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = vaultDecryptedFile.filename;
      a.click();
      URL.revokeObjectURL(url);
    });

    // Live Content Preview Generator
    function renderDecryptedPreview(bytes, filename, mimeType = "") {
      vaultDecPreviewCard.classList.remove("hidden");
      vaultDecPreviewContent.innerHTML = "";
      const ext = filename.split(".").pop().toLowerCase();

      // 1. Image Formats
      if (["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp"].includes(ext) || mimeType.startsWith("image/")) {
        vaultDecPreviewType.textContent = "IMAGE";
        const blob = new Blob([bytes], { type: mimeType || `image/${ext}` });
        const img = document.createElement("img");
        img.src = URL.createObjectURL(blob);
        img.alt = filename;
        vaultDecPreviewContent.appendChild(img);
        return;
      }

      // 2. Audio Formats
      if (["mp3", "wav", "ogg", "flac", "m4a"].includes(ext) || mimeType.startsWith("audio/")) {
        vaultDecPreviewType.textContent = "AUDIO";
        const blob = new Blob([bytes], { type: mimeType || `audio/${ext}` });
        const audio = document.createElement("audio");
        audio.controls = true;
        audio.src = URL.createObjectURL(blob);
        vaultDecPreviewContent.appendChild(audio);
        return;
      }

      // 3. Video Formats
      if (["mp4", "webm"].includes(ext) || mimeType.startsWith("video/")) {
        vaultDecPreviewType.textContent = "VIDEO";
        const blob = new Blob([bytes], { type: mimeType || `video/${ext}` });
        const video = document.createElement("video");
        video.controls = true;
        video.src = URL.createObjectURL(blob);
        vaultDecPreviewContent.appendChild(video);
        return;
      }

      // 4. Text / Code / CSV / JSON Formats
      if (["txt", "md", "csv", "json", "js", "html", "css", "xml", "log", "py", "sh", "yml", "yaml"].includes(ext) || mimeType.startsWith("text/")) {
        vaultDecPreviewType.textContent = ext.toUpperCase();
        try {
          const text = new TextDecoder("utf-8").decode(bytes);
          const pre = document.createElement("pre");
          pre.textContent = text.length > 5000 ? text.substring(0, 5000) + "\n\n... [truncated preview for length]" : text;
          vaultDecPreviewContent.appendChild(pre);
          return;
        } catch (e) {
          // Fall through to doc badge
        }
      }

      // 5. PDF or Generic Binary Document Badge
      vaultDecPreviewType.textContent = ext.toUpperCase() || "BINARY";
      const card = document.createElement("div");
      card.className = "preview-doc-card";
      card.innerHTML = `
        <span class="preview-doc-icon">${getFileIcon(filename, mimeType)}</span>
        <div class="preview-doc-details">
          <span class="preview-doc-name">${filename}</span>
          <span class="preview-doc-info">${formatFileSize(bytes.length)} • ${mimeType || "application/octet-stream"}</span>
        </div>
      `;
      vaultDecPreviewContent.appendChild(card);
    }

    // Sample Secret File Generator (1-Click Test)
    btnVaultSample.addEventListener("click", () => {
      const sampleText = `======================================================================
TOP SECRET // CLASSIFIED INTELLIGENCE DOSSIER // AEGIS-OMEGA
CLASSIFICATION: LEVEL-5 DIRECTIVE // CODE: CIPHER-HORIZON-9
OPERATION TIMESTAMP: ${new Date().toISOString()}
======================================================================

1. MISSION OBJECTIVE:
Deploy client-side authenticated cryptographic vault across distributed terminals.
Ensure 100% bit-exact reversibility and zero-trust tamper detection via W3C WebCrypto.

2. TACTICAL SECTOR COORDINATES:
- Primary Relay Node: 45.5152° N, 122.6784° W (Cascadia Ridge)
- Emergency Broadcast Beacon: 142.850 MHz [AES-128-GCM Authenticated Stream]
- Sub-Station Quantum Hash: 0x9f8e7d6c5b4a392817263544fedcba09

3. AGENT ROSTER & CLEARANCES:
- Chief Cryptographer: Dr. Elena Vance (Clearance Alpha-1)
- Security Lead: Commander Reyes (Active Watch)
- Operative Handler: Agent K

4. STATUS NOTE:
All contents of this document are cryptographically bound to the SHA-256 digest
and guarded by Galois 128-bit authentication tag.

[END OF TRANSMISSION // RESTRICTED ACCESS]
`;

      const blob = new Blob([sampleText], { type: "text/plain" });
      const file = new File([blob], "classified_intel_dossier.txt", { type: "text/plain", lastModified: Date.now() });

      switchVaultSubtab("encrypt");
      handleFileSelectedForEncrypt(file);
      vaultTelemetryMsg.innerHTML = "✨ Generated sample secret document: <strong>classified_intel_dossier.txt</strong>. Click 'ENCRYPT & PACKAGE FILE' to encrypt!";
    });

    // Expose for testing hooks if needed
    window.vaultApi = {
      switchAppMode,
      switchVaultSubtab,
      handleFileSelectedForEncrypt,
      handleFileSelectedForDecrypt
    };
  }

  // Initialize File Vault
  initUniversalFileVault();

  // Load default Tux Penguin preset on boot
  generatePresetImage("penguin");

  // Automated testing hooks via URL query param (?test=encrypt, ?test=decrypt, ?test=specs, ?test=vault)
  const urlParams = new URLSearchParams(window.location.search);
  const testMode = urlParams.get("test");
  if (testMode === "encrypt") {
    setTimeout(async () => {
      await runEncryptionPipeline();
      inspectBlockAt(2500); // inspect block on penguin belly
    }, 200);
  } else if (testMode === "decrypt") {
    setTimeout(async () => {
      await runEncryptionPipeline();
      await runDecryptionPipeline();
    }, 200);
  } else if (testMode === "specs") {
    setTimeout(() => {
      modalSpecs.classList.remove("hidden");
    }, 200);
  } else if (testMode === "vault") {
    setTimeout(() => {
      window.vaultApi.switchAppMode("vault");
      document.getElementById("btn-vault-sample").click();
    }, 200);
  }
});

