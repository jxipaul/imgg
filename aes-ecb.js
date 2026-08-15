/**
 * AES-128 Pure JavaScript Implementation for ECB Mode
 * Supports block-by-block Encryption and Decryption
 */

const AES = (() => {
  // S-Box lookup table
  const SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ]);

  // Inverse S-Box lookup table
  const INVSBOX = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    INVSBOX[SBOX[i]] = i;
  }

  // Round Constant lookup table
  const RCON = new Uint8Array([
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
  ]);

  // Galois Field (2^8) multiplication helpers
  function mul2(b) {
    return (b & 0x80) ? ((b << 1) ^ 0x1b) & 0xff : (b << 1);
  }
  function mul3(b) { return mul2(b) ^ b; }
  function mul9(b) { return mul2(mul2(mul2(b))) ^ b; }
  function mul11(b) { return mul2(mul2(mul2(b)) ^ b) ^ b; }
  function mul13(b) { return mul2(mul2(mul2(b) ^ b)) ^ b; }
  function mul14(b) { return mul2(mul2(mul2(b) ^ b) ^ b); }

  /**
   * Expand 16-byte key into 176-byte round key schedule (11 round keys)
   */
  function expandKey(keyBytes) {
    if (keyBytes.length !== 16) {
      throw new Error("AES-128 requires a 16-byte key.");
    }
    const w = new Uint8Array(176);
    w.set(keyBytes, 0);

    for (let i = 16; i < 176; i += 4) {
      let b0 = w[i - 4];
      let b1 = w[i - 3];
      let b2 = w[i - 2];
      let b3 = w[i - 1];

      if (i % 16 === 0) {
        // RotWord
        const temp = b0;
        b0 = b1;
        b1 = b2;
        b2 = b3;
        b3 = temp;

        // SubWord
        b0 = SBOX[b0];
        b1 = SBOX[b1];
        b2 = SBOX[b2];
        b3 = SBOX[b3];

        // XOR Rcon
        b0 ^= RCON[i / 16];
      }

      w[i]     = w[i - 16] ^ b0;
      w[i + 1] = w[i - 15] ^ b1;
      w[i + 2] = w[i - 14] ^ b2;
      w[i + 3] = w[i - 13] ^ b3;
    }
    return w;
  }

  function addRoundKey(state, w, round) {
    const offset = round * 16;
    for (let i = 0; i < 16; i++) {
      state[i] ^= w[offset + i];
    }
  }

  function subBytes(state) {
    for (let i = 0; i < 16; i++) {
      state[i] = SBOX[state[i]];
    }
  }

  function invSubBytes(state) {
    for (let i = 0; i < 16; i++) {
      state[i] = INVSBOX[state[i]];
    }
  }

  function shiftRows(state) {
    let tmp;
    // Row 1: shift left 1
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2: shift left 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // Row 3: shift left 3 (right 1)
    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
  }

  function invShiftRows(state) {
    let tmp;
    // Row 1: shift right 1
    tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    // Row 2: shift right 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    // Row 3: shift right 3
    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
  }

  function mixColumns(state) {
    for (let c = 0; c < 4; c++) {
      const idx = c * 4;
      const s0 = state[idx];
      const s1 = state[idx + 1];
      const s2 = state[idx + 2];
      const s3 = state[idx + 3];

      state[idx]     = mul2(s0) ^ mul3(s1) ^ s2 ^ s3;
      state[idx + 1] = s0 ^ mul2(s1) ^ mul3(s2) ^ s3;
      state[idx + 2] = s0 ^ s1 ^ mul2(s2) ^ mul3(s3);
      state[idx + 3] = mul3(s0) ^ s1 ^ s2 ^ mul2(s3);
    }
  }

  function invMixColumns(state) {
    for (let c = 0; c < 4; c++) {
      const idx = c * 4;
      const s0 = state[idx];
      const s1 = state[idx + 1];
      const s2 = state[idx + 2];
      const s3 = state[idx + 3];

      state[idx]     = mul14(s0) ^ mul11(s1) ^ mul13(s2) ^ mul9(s3);
      state[idx + 1] = mul9(s0)  ^ mul14(s1) ^ mul11(s2) ^ mul13(s3);
      state[idx + 2] = mul13(s0) ^ mul9(s1)  ^ mul14(s2) ^ mul11(s3);
      state[idx + 3] = mul11(s0) ^ mul13(s1) ^ mul9(s2)  ^ mul14(s3);
    }
  }

  /**
   * Encrypt a single 16-byte block
   */
  function encryptBlock(block, roundKeys) {
    const state = new Uint8Array(block);
    addRoundKey(state, roundKeys, 0);

    for (let round = 1; round < 10; round++) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, roundKeys, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys, 10);

    return state;
  }

  /**
   * Decrypt a single 16-byte block
   */
  function decryptBlock(block, roundKeys) {
    const state = new Uint8Array(block);
    addRoundKey(state, roundKeys, 10);

    for (let round = 9; round > 0; round--) {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, roundKeys, round);
      invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys, 0);

    return state;
  }

  /**
   * Encrypt data in ECB mode (independent 16-byte blocks)
   */
  function ecbEncrypt(data, keyBytes) {
    const roundKeys = expandKey(keyBytes);
    const output = new Uint8Array(data.length);

    for (let i = 0; i < data.length; i += 16) {
      const block = data.subarray(i, i + 16);
      // If block is smaller than 16 (end of array), pad with zeros
      let inputBlock = block;
      if (block.length < 16) {
        inputBlock = new Uint8Array(16);
        inputBlock.set(block);
      }
      const encBlock = encryptBlock(inputBlock, roundKeys);
      output.set(encBlock.subarray(0, block.length), i);
    }

    return output;
  }

  /**
   * Decrypt data in ECB mode (independent 16-byte blocks)
   */
  function ecbDecrypt(ciphertext, keyBytes) {
    const roundKeys = expandKey(keyBytes);
    const output = new Uint8Array(ciphertext.length);

    for (let i = 0; i < ciphertext.length; i += 16) {
      const block = ciphertext.subarray(i, i + 16);
      let inputBlock = block;
      if (block.length < 16) {
        inputBlock = new Uint8Array(16);
        inputBlock.set(block);
      }
      const decBlock = decryptBlock(inputBlock, roundKeys);
      output.set(decBlock.subarray(0, block.length), i);
    }

    return output;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { expandKey, encryptBlock, decryptBlock, ecbEncrypt, ecbDecrypt };
  }
  return {
    expandKey,
    encryptBlock,
    decryptBlock,
    ecbEncrypt,
    ecbDecrypt
  };
})();

if (typeof window !== 'undefined') {
  window.AES = AES;
}

