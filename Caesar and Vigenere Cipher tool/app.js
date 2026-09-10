/**
 * Cryptography Engine & Cryptanalysis Studio
 * Implements Caesar & Vigenère ciphers, Chi-Squared Goodness of Fit, and IoC auto-cracking.
 */

// Standard English Letter Frequencies
const ENGLISH_FREQ = {
  A: 0.08167, B: 0.01492, C: 0.02782, D: 0.04253, E: 0.12702,
  F: 0.02228, G: 0.02015, H: 0.06094, I: 0.06966, J: 0.00153,
  K: 0.00772, L: 0.04025, M: 0.02406, N: 0.06749, O: 0.07507,
  P: 0.01929, Q: 0.00095, R: 0.05987, S: 0.06327, T: 0.09056,
  U: 0.02758, V: 0.00978, W: 0.02360, X: 0.00150, Y: 0.01974,
  Z: 0.00074
};

const ENGLISH_IOC = 0.0667;
const RANDOM_IOC = 0.0385;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// ==========================================
// 1. CORE CIPHERS
// ==========================================

function caesarCipher(text, shift, decrypt = false) {
  shift = (shift % 26 + 26) % 26;
  if (decrypt) shift = (26 - shift) % 26;

  let result = "";
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char >= 'A' && char <= 'Z') {
      const code = (char.charCodeAt(0) - 65 + shift) % 26;
      result += String.fromCharCode(code + 65);
    } else if (char >= 'a' && char <= 'z') {
      const code = (char.charCodeAt(0) - 97 + shift) % 26;
      result += String.fromCharCode(code + 97);
    } else {
      result += char;
    }
  }
  return result;
}

function vigenereCipher(text, key, decrypt = false) {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "");
  if (!cleanKey) return text;

  let result = "";
  let keyIdx = 0;
  const keyLen = cleanKey.length;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (/[a-zA-Z]/.test(char)) {
      let shift = cleanKey.charCodeAt(keyIdx % keyLen) - 65;
      if (decrypt) shift = (26 - shift) % 26;

      if (char >= 'A' && char <= 'Z') {
        const code = (char.charCodeAt(0) - 65 + shift) % 26;
        result += String.fromCharCode(code + 65);
      } else {
        const code = (char.charCodeAt(0) - 97 + shift) % 26;
        result += String.fromCharCode(code + 97);
      }
      keyIdx++;
    } else {
      result += char;
    }
  }
  return result;
}

// ==========================================
// 2. STATISTICAL CRYPTANALYSIS
// ==========================================

function getLetterCounts(text) {
  const counts = {};
  for (const c of ALPHABET) counts[c] = 0;
  let total = 0;

  for (let i = 0; i < text.length; i++) {
    const char = text[i].toUpperCase();
    if (char >= 'A' && char <= 'Z') {
      counts[char]++;
      total++;
    }
  }
  return { counts, total };
}

function calculateChiSquared(text) {
  const { counts, total } = getLetterCounts(text);
  if (total === 0) return 9999.0;

  let chiSq = 0;
  for (const char of ALPHABET) {
    const expected = total * ENGLISH_FREQ[char];
    const observed = counts[char];
    chiSq += Math.pow(observed - expected, 2) / expected;
  }
  return chiSq;
}

function calculateIoC(text) {
  const { counts, total } = getLetterCounts(text);
  if (total <= 1) return 0;

  let sum = 0;
  for (const char of ALPHABET) {
    sum += counts[char] * (counts[char] - 1);
  }
  return sum / (total * (total - 1));
}

// ==========================================
// 3. AUTOMATED CRACKERS
// ==========================================

function breakCaesar(ciphertext) {
  let bestShift = 0;
  let minChi = Infinity;
  const candidates = [];

  for (let shift = 0; shift < 26; shift++) {
    const candidate = caesarCipher(ciphertext, shift, true);
    const score = calculateChiSquared(candidate);
    candidates.push({ shift, score, preview: candidate.substring(0, 45) });
    if (score < minChi) {
      minChi = score;
      bestShift = shift;
    }
  }

  candidates.sort((a, b) => a.score - b.score);

  return {
    bestShift,
    minChi,
    plaintext: caesarCipher(ciphertext, bestShift, true),
    candidates
  };
}

function findVigenereKeyLength(ciphertext, maxLen = 16) {
  const cleanLetters = ciphertext.toUpperCase().replace(/[^A-Z]/g, "");
  if (cleanLetters.length < 10) return [{ length: 1, ioc: 0 }];

  const results = [];
  const upperTest = Math.min(maxLen, Math.floor(cleanLetters.length / 2));

  for (let k = 1; k <= upperTest; k++) {
    let sumIoC = 0;
    for (let i = 0; i < k; i++) {
      let slice = "";
      for (let j = i; j < cleanLetters.length; j += k) {
        slice += cleanLetters[j];
      }
      sumIoC += calculateIoC(slice);
    }
    const avgIoC = sumIoC / k;
    results.push({ length: k, ioc: avgIoC, diff: Math.abs(avgIoC - ENGLISH_IOC) });
  }

  results.sort((a, b) => a.diff - b.diff);
  return results;
}

function breakVigenere(ciphertext, knownLength = null) {
  const cleanLetters = ciphertext.toUpperCase().replace(/[^A-Z]/g, "");
  const lengthRankings = findVigenereKeyLength(ciphertext);
  const keyLen = knownLength && knownLength > 0 ? knownLength : lengthRankings[0].length;

  let recoveredKey = "";
  const sliceDetails = [];

  for (let i = 0; i < keyLen; i++) {
    let slice = "";
    for (let j = i; j < cleanLetters.length; j += keyLen) {
      slice += cleanLetters[j];
    }
    const caesarResult = breakCaesar(slice);
    const shift = caesarResult.bestShift;
    const keyLetter = String.fromCharCode(65 + shift);
    recoveredKey += keyLetter;
    sliceDetails.push({
      index: i + 1,
      keyLetter,
      shift,
      chi: caesarResult.minChi
    });
  }

  const decrypted = vigenereCipher(ciphertext, recoveredKey, true);
  const overallChi = calculateChiSquared(decrypted);

  return {
    recoveredKey,
    keyLength: keyLen,
    lengthRankings,
    sliceDetails,
    decrypted,
    overallChi
  };
}

// ==========================================
// 4. UI INTERACTION & EVENT LISTENERS
// ==========================================

let activeCipher = "caesar"; // 'caesar' | 'vigenere'
let activeMode = "encrypt";  // 'encrypt' | 'decrypt' | 'crack'

const PRESETS = {
  sample1: "Cryptography is the practice and study of techniques for secure communication in the presence of adversarial third parties. Classical ciphers build the intuition for modern encryption protocols like AES and RSA.",
  sample2: "The quick brown fox jumps over the lazy dog repeatedly to exhibit typical English letter frequency patterns.",
  sample3: "Wklv phvvdjh zdv hqfubswhg xvlqj wkh fdhvdu fhvsxu zlwk d vhfuhw vhylqj vhwwlqj ri wkuhh."
};

document.addEventListener("DOMContentLoaded", () => {
  initUI();
  updateCalculations();
});

function initUI() {
  // Cipher Tabs
  document.getElementById("tab-caesar").addEventListener("click", () => {
    activeCipher = "caesar";
    setActiveTab("cipher", "tab-caesar");
    document.getElementById("caesar-controls").style.display = "block";
    document.getElementById("vigenere-controls").style.display = "none";
    updateCalculations();
  });

  document.getElementById("tab-vigenere").addEventListener("click", () => {
    activeCipher = "vigenere";
    setActiveTab("cipher", "tab-vigenere");
    document.getElementById("caesar-controls").style.display = "none";
    document.getElementById("vigenere-controls").style.display = "block";
    updateCalculations();
  });

  // Mode Tabs
  document.getElementById("mode-encrypt").addEventListener("click", () => {
    activeMode = "encrypt";
    setActiveTab("mode", "mode-encrypt");
    document.getElementById("crack-output-panel").style.display = "none";
    document.getElementById("standard-output-panel").style.display = "block";
    updateCalculations();
  });

  document.getElementById("mode-decrypt").addEventListener("click", () => {
    activeMode = "decrypt";
    setActiveTab("mode", "mode-decrypt");
    document.getElementById("crack-output-panel").style.display = "none";
    document.getElementById("standard-output-panel").style.display = "block";
    updateCalculations();
  });

  document.getElementById("mode-crack").addEventListener("click", () => {
    activeMode = "crack";
    setActiveTab("mode", "mode-crack");
    document.getElementById("crack-output-panel").style.display = "block";
    document.getElementById("standard-output-panel").style.display = "none";
    updateCalculations();
  });

  // Input Listeners
  const inputTextArea = document.getElementById("inputText");
  inputTextArea.addEventListener("input", updateCalculations);

  const caesarShiftSlider = document.getElementById("caesarShift");
  caesarShiftSlider.addEventListener("input", (e) => {
    document.getElementById("shiftValDisplay").innerText = e.target.value;
    updateCalculations();
  });

  const vigenereKeyInput = document.getElementById("vigenereKey");
  vigenereKeyInput.addEventListener("input", updateCalculations);

  // Preset Buttons
  document.getElementById("btn-preset-1").addEventListener("click", () => {
    inputTextArea.value = PRESETS.sample1;
    updateCalculations();
  });

  document.getElementById("btn-preset-2").addEventListener("click", () => {
    inputTextArea.value = PRESETS.sample2;
    updateCalculations();
  });

  // Copy Buttons
  document.getElementById("btn-copy-output").addEventListener("click", () => {
    const out = document.getElementById("outputText").value;
    navigator.clipboard.writeText(out).then(() => showTooltip("copy-tip-1"));
  });

  document.getElementById("btn-copy-cracked").addEventListener("click", () => {
    const out = document.getElementById("crackedPlaintext").innerText;
    navigator.clipboard.writeText(out).then(() => showTooltip("copy-tip-2"));
  });

  // Render Base Chart
  renderChartSkeleton();
}

function setActiveTab(group, activeId) {
  if (group === "cipher") {
    document.querySelectorAll(".cipher-tab").forEach(t => t.classList.remove("active"));
    document.getElementById(activeId).classList.add("active");
  } else if (group === "mode") {
    document.querySelectorAll(".mode-tab").forEach(t => t.classList.remove("active"));
    document.getElementById(activeId).classList.add("active");
  }
}

function showTooltip(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.add("show");
    setTimeout(() => el.classList.remove("show"), 1800);
  }
}

function renderChartSkeleton() {
  const container = document.getElementById("chartBars");
  container.innerHTML = "";
  for (const char of ALPHABET) {
    const col = document.createElement("div");
    col.className = "bar-col";
    col.innerHTML = `
      <div class="bar-pair">
        <div class="bar-observed" id="bar-obs-${char}" style="height: 0%"></div>
        <div class="bar-expected" id="bar-exp-${char}" style="height: ${ENGLISH_FREQ[char] * 400}%"></div>
      </div>
      <span class="bar-label">${char}</span>
    `;
    container.appendChild(col);
  }
}

// ==========================================
// 5. MASTER CALCULATION & UI REFRESH
// ==========================================

function updateCalculations() {
  const inputText = document.getElementById("inputText").value;
  const { counts, total } = getLetterCounts(inputText);

  // 1. Update Statistical Metrics
  const ioc = calculateIoC(inputText);
  const chi = calculateChiSquared(inputText);
  document.getElementById("metric-ioc").innerText = ioc.toFixed(4);
  document.getElementById("metric-chi").innerText = chi.toFixed(2);
  document.getElementById("metric-count").innerText = total;

  // 2. Update Frequency Bars
  for (const char of ALPHABET) {
    const obsPct = total > 0 ? (counts[char] / total) : 0;
    const bar = document.getElementById(`bar-obs-${char}`);
    if (bar) {
      bar.style.height = `${Math.min(obsPct * 400, 100)}%`;
      bar.title = `${char}: Observed ${(obsPct * 100).toFixed(1)}% | English ${(ENGLISH_FREQ[char] * 100).toFixed(1)}%`;
    }
  }

  // 3. Perform Cipher Operation
  if (activeMode === "encrypt" || activeMode === "decrypt") {
    let result = "";
    if (activeCipher === "caesar") {
      const shift = parseInt(document.getElementById("caesarShift").value, 10);
      result = caesarCipher(inputText, shift, activeMode === "decrypt");
    } else {
      const key = document.getElementById("vigenereKey").value || "KEY";
      result = vigenereCipher(inputText, key, activeMode === "decrypt");
    }
    document.getElementById("outputText").value = result;
  } else if (activeMode === "crack") {
    performAutoCrack(inputText);
  }
}

function performAutoCrack(ciphertext) {
  const detailsContainer = document.getElementById("crackDetails");
  const crackedTextField = document.getElementById("crackedPlaintext");

  if (!ciphertext.trim()) {
    detailsContainer.innerHTML = "<p style='color: var(--text-muted)'>Enter ciphertext to begin automated cryptanalysis.</p>";
    crackedTextField.innerText = "";
    return;
  }

  if (activeCipher === "caesar") {
    const res = breakCaesar(ciphertext);
    crackedTextField.innerText = res.plaintext;

    let html = `
      <div class="crack-step">
        <div class="step-num">1</div>
        <div>
          <strong style="color: var(--accent-cyan)">Frequency Goodness-of-Fit Test (Chi-Squared):</strong><br>
          Evaluated all 26 possible shifts. Minimum χ² score: <strong>${res.minChi.toFixed(2)}</strong> at <strong>Shift ${res.bestShift}</strong>.
        </div>
      </div>
      <div class="crack-step">
        <div class="step-num">2</div>
        <div>
          <strong style="color: var(--accent-cyan)">Candidate Shifts Ranking:</strong>
          <table style="width: 100%; margin-top: 8px; border-collapse: collapse; font-size: 0.82rem;">
            <tr style="color: var(--text-muted); border-bottom: 1px solid rgba(255,255,255,0.1);">
              <th style="text-align: left; padding: 4px;">Rank</th>
              <th style="text-align: left; padding: 4px;">Shift</th>
              <th style="text-align: left; padding: 4px;">Chi-Squared (χ²)</th>
              <th style="text-align: left; padding: 4px;">Decrypted Sample</th>
            </tr>
    `;

    res.candidates.slice(0, 3).forEach((c, idx) => {
      html += `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); color: ${idx === 0 ? '#10b981' : 'inherit'}; font-weight: ${idx === 0 ? '700' : 'normal'}">
          <td style="padding: 4px;">#${idx + 1}</td>
          <td style="padding: 4px;">${c.shift}</td>
          <td style="padding: 4px;">${c.score.toFixed(2)}</td>
          <td style="padding: 4px;">${escapeHtml(c.preview)}...</td>
        </tr>
      `;
    });

    html += `</table></div></div>`;
    detailsContainer.innerHTML = html;

  } else if (activeCipher === "vigenere") {
    const res = breakVigenere(ciphertext);
    crackedTextField.innerText = res.decrypted;

    let html = `
      <div class="crack-step">
        <div class="step-num">1</div>
        <div>
          <strong style="color: var(--accent-purple)">Index of Coincidence (IoC) Key Length Detection:</strong><br>
          Average coincidence rate peaked at key length <strong>${res.keyLength}</strong> (Avg IoC: ${(res.lengthRankings[0].ioc).toFixed(4)} vs English 0.0667).
        </div>
      </div>
      <div class="crack-step">
        <div class="step-num">2</div>
        <div>
          <strong style="color: var(--accent-purple)">Recovered Keyword:</strong> 
          <span style="background: rgba(168,85,247,0.25); color: #c084fc; padding: 3px 8px; border-radius: 4px; font-weight: 700;">${res.recoveredKey}</span>
        </div>
      </div>
      <div class="crack-step">
        <div class="step-num">3</div>
        <div>
          <strong style="color: var(--accent-purple)">Coset Slice Frequency Breakdown:</strong>
          <table style="width: 100%; margin-top: 8px; border-collapse: collapse; font-size: 0.82rem;">
            <tr style="color: var(--text-muted); border-bottom: 1px solid rgba(255,255,255,0.1);">
              <th style="text-align: left; padding: 4px;">Slice #</th>
              <th style="text-align: left; padding: 4px;">Caesar Shift</th>
              <th style="text-align: left; padding: 4px;">Key Char</th>
              <th style="text-align: left; padding: 4px;">Slice χ²</th>
            </tr>
    `;

    res.sliceDetails.forEach(s => {
      html += `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <td style="padding: 4px;">Slice ${s.index}</td>
          <td style="padding: 4px;">${s.shift}</td>
          <td style="padding: 4px; color: #38bdf8; font-weight: 700;">${s.keyLetter}</td>
          <td style="padding: 4px;">${s.chi.toFixed(2)}</td>
        </tr>
      `;
    });

    html += `</table></div></div>`;
    detailsContainer.innerHTML = html;
  }
}

function escapeHtml(string) {
  return String(string).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
