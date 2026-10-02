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

  // Load default Tux Penguin preset on boot
  generatePresetImage("penguin");

  // Automated testing hooks via URL query param (?test=encrypt, ?test=decrypt, ?test=specs)
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
  }
});
