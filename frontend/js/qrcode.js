// Encodeur QR minimal (mode octet, versions 1-6, ECC L), sans dependance.
// Verifie par decodage bit-a-bit contre une reference (voir memoire de session).

const GF_EXP = new Array(512);
const GF_LOG = new Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], 1);
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(dataBytes, ecCount) {
  const generator = rsGeneratorPoly(ecCount);
  const result = dataBytes.slice();
  for (let i = 0; i < ecCount; i++) result.push(0);
  for (let i = 0; i < dataBytes.length; i++) {
    const coeff = result[i];
    if (coeff === 0) continue;
    for (let j = 0; j < generator.length; j++) {
      result[i + j] ^= gfMul(generator[j], coeff);
    }
  }
  return result.slice(dataBytes.length);
}

// Table des blocs pour ECC=L, versions 1-6.
const VERSION_INFO_L = {
  1: { g1blocks: 1, g1data: 19, g2blocks: 0, g2data: 0, ecPerBlock: 7 },
  2: { g1blocks: 1, g1data: 34, g2blocks: 0, g2data: 0, ecPerBlock: 10 },
  3: { g1blocks: 1, g1data: 55, g2blocks: 0, g2data: 0, ecPerBlock: 15 },
  4: { g1blocks: 1, g1data: 80, g2blocks: 0, g2data: 0, ecPerBlock: 20 },
  5: { g1blocks: 1, g1data: 108, g2blocks: 0, g2data: 0, ecPerBlock: 26 },
  6: { g1blocks: 2, g1data: 68, g2blocks: 0, g2data: 0, ecPerBlock: 18 },
};

const ALIGNMENT_CENTER = { 2: 18, 3: 22, 4: 26, 5: 30, 6: 34 };

function sizeForVersion(version) {
  return 17 + 4 * version;
}

export function byteCapacity(version) {
  const info = VERSION_INFO_L[version];
  const totalData = info.g1blocks * info.g1data + info.g2blocks * info.g2data;
  return Math.floor((totalData * 8 - 4 - 8 - 4) / 8);
}

function chooseVersion(byteLength) {
  for (let v = 1; v <= 6; v++) {
    if (byteLength <= byteCapacity(v)) return v;
  }
  throw new Error(`Contenu trop long pour un QR code (max ${byteCapacity(6)} octets, version <=6).`);
}

function buildDataCodewords(bytes, version) {
  const info = VERSION_INFO_L[version];
  const totalDataCodewords = info.g1blocks * info.g1data + info.g2blocks * info.g2data;

  const bits = [];
  const pushBits = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >> i) & 1);
  };

  pushBits(0b0100, 4); // mode octet
  pushBits(bytes.length, 8); // indicateur de longueur (versions 1-9)
  for (const byte of bytes) pushBits(byte, 8);
  pushBits(0, Math.min(4, totalDataCodewords * 8 - bits.length));

  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    codewords.push(byte);
  }

  const padBytes = [0xec, 0x11];
  let padIndex = 0;
  while (codewords.length < totalDataCodewords) {
    codewords.push(padBytes[padIndex % 2]);
    padIndex++;
  }
  return codewords;
}

function splitAndInterleave(dataCodewords, version) {
  const info = VERSION_INFO_L[version];
  const blocks = [];
  let offset = 0;
  for (let i = 0; i < info.g1blocks; i++) {
    blocks.push(dataCodewords.slice(offset, offset + info.g1data));
    offset += info.g1data;
  }
  for (let i = 0; i < info.g2blocks; i++) {
    blocks.push(dataCodewords.slice(offset, offset + info.g2data));
    offset += info.g2data;
  }

  const ecBlocks = blocks.map((block) => rsEncode(block, info.ecPerBlock));

  const interleaved = [];
  const maxDataLen = Math.max(...blocks.map((b) => b.length));
  for (let i = 0; i < maxDataLen; i++) {
    for (const block of blocks) {
      if (i < block.length) interleaved.push(block[i]);
    }
  }
  for (let i = 0; i < info.ecPerBlock; i++) {
    for (const ecBlock of ecBlocks) {
      interleaved.push(ecBlock[i]);
    }
  }
  return interleaved;
}

function createMatrix(size) {
  const matrix = [];
  for (let i = 0; i < size; i++) matrix.push(new Array(size).fill(null));
  return matrix;
}

function placeFinderPattern(matrix, row, col) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || cc < 0 || rr >= matrix.length || cc >= matrix.length) continue;
      const inBox = r >= 0 && r <= 6 && c >= 0 && c <= 6;
      const isFinder =
        inBox && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
      matrix[rr][cc] = inBox ? (isFinder ? 1 : 0) : 0;
    }
  }
}

function placeAlignmentPattern(matrix, row, col) {
  for (let r = -2; r <= 2; r++) {
    for (let c = -2; c <= 2; c++) {
      const isDark = r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0);
      matrix[row + r][col + c] = isDark ? 1 : 0;
    }
  }
}

function placeFunctionPatterns(matrix, version) {
  const size = matrix.length;
  placeFinderPattern(matrix, 0, 0);
  placeFinderPattern(matrix, 0, size - 7);
  placeFinderPattern(matrix, size - 7, 0);

  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2 === 0 ? 1 : 0;
    matrix[i][6] = i % 2 === 0 ? 1 : 0;
  }

  if (version >= 2) {
    const center = ALIGNMENT_CENTER[version];
    placeAlignmentPattern(matrix, center, center);
  }

  matrix[size - 8][8] = 1; // module noir fixe

  for (let i = 0; i < 9; i++) {
    if (matrix[8][i] === null) matrix[8][i] = -1;
    if (matrix[i][8] === null) matrix[i][8] = -1;
  }
  for (let i = size - 8; i < size; i++) {
    if (matrix[8][i] === null) matrix[8][i] = -1;
    if (matrix[i][8] === null) matrix[i][8] = -1;
  }
}

function placeDataBits(matrix, codewords) {
  const size = matrix.length;
  const bits = [];
  for (const byte of codewords) {
    for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  }

  let bitIndex = 0;
  let inc = -1;
  let row = size - 1;

  // Zigzag standard : sauter la colonne 6 (timing pattern) en decalant tout
  // le reste d'un cran, pas en la traitant comme une paire isolee — sinon la
  // colonne 0 se retrouve sans binome et jamais visitee.
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;

    while (true) {
      for (let c = 0; c < 2; c++) {
        if (matrix[row][col - c] === null) {
          const bit = bitIndex < bits.length ? bits[bitIndex] : 0;
          matrix[row][col - c] = { data: bit };
          bitIndex++;
        }
      }

      row += inc;
      if (row < 0 || row >= size) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
}

function applyMask(matrix, maskId, functionMask) {
  const size = matrix.length;
  const out = createMatrix(size);
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      const cell = matrix[r][c];
      const isData = typeof cell === "object" && cell !== null;
      const baseValue = isData ? cell.data : cell === -1 ? 0 : cell;
      if (functionMask[r][c]) {
        out[r][c] = baseValue;
        continue;
      }
      let invert;
      switch (maskId) {
        case 0:
          invert = (r + c) % 2 === 0;
          break;
        case 1:
          invert = r % 2 === 0;
          break;
        case 2:
          invert = c % 3 === 0;
          break;
        case 3:
          invert = (r + c) % 3 === 0;
          break;
        case 4:
          invert = (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
          break;
        case 5:
          invert = ((r * c) % 2) + ((r * c) % 3) === 0;
          break;
        case 6:
          invert = (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
          break;
        case 7:
          invert = (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
          break;
        default:
          invert = false;
      }
      out[r][c] = invert ? baseValue ^ 1 : baseValue;
    }
  }
  return out;
}

function penaltyScore(matrix) {
  const size = matrix.length;
  let score = 0;

  for (let r = 0; r < size; r++) {
    let runColor = matrix[r][0];
    let runLength = 1;
    for (let c = 1; c < size; c++) {
      if (matrix[r][c] === runColor) {
        runLength++;
      } else {
        if (runLength >= 5) score += 3 + (runLength - 5);
        runColor = matrix[r][c];
        runLength = 1;
      }
    }
    if (runLength >= 5) score += 3 + (runLength - 5);
  }

  for (let c = 0; c < size; c++) {
    let runColor = matrix[0][c];
    let runLength = 1;
    for (let r = 1; r < size; r++) {
      if (matrix[r][c] === runColor) {
        runLength++;
      } else {
        if (runLength >= 5) score += 3 + (runLength - 5);
        runColor = matrix[r][c];
        runLength = 1;
      }
    }
    if (runLength >= 5) score += 3 + (runLength - 5);
  }

  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = matrix[r][c];
      if (v === matrix[r][c + 1] && v === matrix[r + 1][c] && v === matrix[r + 1][c + 1]) {
        score += 3;
      }
    }
  }

  let darkCount = 0;
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) darkCount += matrix[r][c];
  const percent = (darkCount * 100) / (size * size);
  const deviation = Math.floor(Math.abs(percent - 50) / 5);
  score += deviation * 10;

  return score;
}

function generateFormatBits(maskId) {
  const eccBits = 0b01; // niveau L
  const data = (eccBits << 3) | maskId;
  let bch = data << 10;
  const generator = 0b10100110111;
  for (let i = 4; i >= 0; i--) {
    if (bch & (1 << (i + 10))) {
      bch ^= generator << i;
    }
  }
  return ((data << 10) | bch) ^ 0b101010000010010;
}

function placeFormatInfo(matrix, maskId) {
  // Deux copies completes des 15 bits : une verticale (colonne 8), une
  // horizontale (ligne 8), chacune scindee en deux moities pres des coins.
  const size = matrix.length;
  const bits = generateFormatBits(maskId);

  for (let i = 0; i < 15; i++) {
    const bit = (bits >> i) & 1;

    if (i < 6) matrix[i][8] = bit;
    else if (i < 8) matrix[i + 1][8] = bit;
    else matrix[size - 15 + i][8] = bit;

    if (i < 8) matrix[8][size - i - 1] = bit;
    else if (i < 9) matrix[8][15 - i] = bit;
    else matrix[8][14 - i] = bit;
  }
}

/**
 * Encode `text` (UTF-8, mode octet) en QR code, ECC=L, version 1-6.
 * Retourne { size, matrix } ou matrix[row][col] vaut 0 ou 1.
 */
export function encodeQr(text) {
  const bytes = Array.from(new TextEncoder().encode(text));
  const version = chooseVersion(bytes.length);
  const size = sizeForVersion(version);

  const dataCodewords = buildDataCodewords(bytes, version);
  const finalCodewords = splitAndInterleave(dataCodewords, version);

  const template = createMatrix(size);
  placeFunctionPatterns(template, version);

  const functionMask = createMatrix(size);
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      functionMask[r][c] = template[r][c] !== null;
    }
  }

  const withData = template.map((row) => row.slice());
  placeDataBits(withData, finalCodewords);

  let best = null;
  for (let maskId = 0; maskId < 8; maskId++) {
    const masked = applyMask(withData, maskId, functionMask);
    placeFormatInfo(masked, maskId);
    const score = penaltyScore(masked);
    if (!best || score < best.score) best = { score, matrix: masked, maskId };
  }

  return { size, matrix: best.matrix };
}

/**
 * Dessine `text` en QR code sur un <canvas> existant (module carre, fond blanc, marge).
 */
export function drawQrToCanvas(canvas, text, { moduleSize = 6, margin = 4 } = {}) {
  const { size, matrix } = encodeQr(text);
  const totalModules = size + margin * 2;
  const pixels = totalModules * moduleSize;
  canvas.width = pixels;
  canvas.height = pixels;

  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, pixels, pixels);
  ctx.fillStyle = "#000000";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] !== 1) continue;
      ctx.fillRect((c + margin) * moduleSize, (r + margin) * moduleSize, moduleSize, moduleSize);
    }
  }
}
