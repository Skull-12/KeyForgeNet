/**
 * KeyForge - Cryptographically Secure Password Generator
 * Vanilla JavaScript (script.js)
 * 
 * Demonstrates:
 * 1. Using window.crypto.getRandomValues() for cryptographically secure randomness
 * 2. Clean DOM manipulation and reactive updates without any frameworks
 * 3. Clipboard API integration with fallback
 * 4. Password entropy and strength calculation
 */

// ==========================================
// 1. Character Sets Definition
// ==========================================
const CHARACTER_SETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  // Curated, safe symbols commonly accepted across platforms:
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?"
};

// ==========================================
// 2. DOM Elements Selection
// ==========================================
const passwordInput = document.getElementById("passwordOutput");
const copyBtn = document.getElementById("copyBtn");
const copyIconBtn = document.getElementById("copyIconBtn");
const refreshBtn = document.getElementById("refreshBtn");
const generateBtn = document.getElementById("generateBtn");

const lengthSlider = document.getElementById("lengthSlider");
const lengthValue = document.getElementById("lengthValue");
const presetButtons = document.querySelectorAll(".btn-preset");

const toggleUppercase = document.getElementById("toggleUppercase");
const toggleLowercase = document.getElementById("toggleLowercase");
const toggleNumbers = document.getElementById("toggleNumbers");
const toggleSymbols = document.getElementById("toggleSymbols");
const warningToast = document.getElementById("warningToast");

const strengthBadge = document.getElementById("strengthBadge");
const strengthBars = document.querySelectorAll(".bar");
const strengthInfo = document.getElementById("strengthInfo");
const toast = document.getElementById("toast");

// ==========================================
// 3. Cryptographically Secure Random Utilities
// ==========================================

/**
 * Generates an unbiased random integer between 0 and (max - 1).
 * Uses window.crypto.getRandomValues() with rejection sampling
 * to eliminate modulo bias.
 * 
 * @param {number} max - The exclusive upper bound.
 * @returns {number} Random integer in [0, max - 1].
 */
function getSecureRandomInt(max) {
  if (max <= 0) return 0;
  
  // Rejection sampling threshold to avoid modulo bias:
  const maxUint32 = 0xFFFFFFFF;
  const limit = Math.floor(maxUint32 / max) * max;
  
  const buffer = new Uint32Array(1);
  let randomVal;
  
  do {
    window.crypto.getRandomValues(buffer);
    randomVal = buffer[0];
  } while (randomVal >= limit);
  
  return randomVal % max;
}

/**
 * Fisher-Yates shuffle implementation powered by crypto.getRandomValues().
 * Ensures every permutation of characters is equally likely.
 * 
 * @param {Array} array - The array to shuffle in-place.
 * @returns {Array} Shuffled array.
 */
function secureShuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(i + 1);
    const temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
  return array;
}

// ==========================================
// 4. Core Password Generation Logic
// ==========================================

/**
 * Generates a secure random password based on current user settings.
 */
function generatePassword() {
  const length = parseInt(lengthSlider.value, 10);
  
  // Collect active character sets:
  const activeSets = [];
  if (toggleUppercase.checked) activeSets.push(CHARACTER_SETS.uppercase);
  if (toggleLowercase.checked) activeSets.push(CHARACTER_SETS.lowercase);
  if (toggleNumbers.checked) activeSets.push(CHARACTER_SETS.numbers);
  if (toggleSymbols.checked) activeSets.push(CHARACTER_SETS.symbols);

  // Fallback guard: if all were somehow deselected, restore lowercase
  if (activeSets.length === 0) {
    toggleLowercase.checked = true;
    activeSets.push(CHARACTER_SETS.lowercase);
  }

  const passwordChars = [];

  // 1. Guarantee at least one character from each selected category
  // This prevents generating an "uppercase+numbers" password that accidentally has no numbers.
  activeSets.forEach(set => {
    const randomIdx = getSecureRandomInt(set.length);
    passwordChars.push(set[randomIdx]);
  });

  // 2. Build the combined pool of all enabled characters
  const fullPool = activeSets.join("");

  // 3. Fill the remainder of the requested password length
  while (passwordChars.length < length) {
    const randomIdx = getSecureRandomInt(fullPool.length);
    passwordChars.push(fullPool[randomIdx]);
  }

  // 4. Shuffle all characters so guaranteed characters aren't clustered at the start
  secureShuffle(passwordChars);

  const finalPassword = passwordChars.join("");
  
  // Render output
  passwordInput.value = finalPassword;

  // Update password strength indicator
  evaluateStrength(finalPassword, activeSets.length, length);

  // Trigger brief display animation
  animateDisplay();
}

/**
 * Adds a small pop/glow animation to the password display
 */
function animateDisplay() {
  passwordInput.style.transform = "scale(0.98)";
  passwordInput.style.transition = "transform 0.1s ease";
  setTimeout(() => {
    passwordInput.style.transform = "scale(1)";
  }, 100);
}

// ==========================================
// 5. Password Strength Evaluation
// ==========================================

/**
 * Evaluates the strength of the generated password based on:
 * - Length
 * - Diversity of character pools (uppercase, lowercase, numbers, symbols)
 * 
 * @param {string} password 
 * @param {number} poolCount 
 * @param {number} length 
 */
function evaluateStrength(password, poolCount, length) {
  let score = 0;

  // Length scoring
  if (length >= 8) score += 1;
  if (length >= 12) score += 1;
  if (length >= 16) score += 1;
  if (length >= 24) score += 1;

  // Character variety bonus/penalty
  if (poolCount === 1) score = Math.min(score, 1);
  if (poolCount >= 3 && length >= 12) score += 1;
  if (poolCount === 4 && length >= 14) score += 1;

  // Map score (1 to 6) to 4 discrete levels: Weak (0), Fair (1), Strong (2), Very Strong (3)
  let level = 0;
  let label = "Weak";
  let badgeClass = "weak";
  let tip = "Short or simple passwords can be cracked quickly.";

  if (score <= 2) {
    level = 0;
    label = "Weak";
    badgeClass = "weak";
    tip = "Increase length or add varied character types.";
  } else if (score <= 3) {
    level = 1;
    label = "Fair";
    badgeClass = "fair";
    tip = "Decent protection. Aim for 14+ characters for higher security.";
  } else if (score <= 4) {
    level = 2;
    label = "Strong";
    badgeClass = "strong";
    tip = "Excellent complexity. Resistant to brute-force attempts.";
  } else {
    level = 3;
    label = "Very Strong";
    badgeClass = "very-strong";
    tip = "Cryptographically robust. Top-tier entropy.";
  }

  // Update Strength Label & Badge
  strengthBadge.textContent = label;
  strengthBadge.className = `strength-badge ${badgeClass}`;
  strengthInfo.textContent = `${length} characters • ${tip}`;

  // Update 4 indicator bars
  strengthBars.forEach((bar, index) => {
    bar.className = "bar";
    if (index <= level) {
      bar.classList.add(`active-${badgeClass}`);
    }
  });
}

// ==========================================
// 6. Clipboard Copy Handling
// ==========================================

let toastTimeout = null;

/**
 * Copies the current password to the clipboard with modern API and fallback.
 */
async function copyPasswordToClipboard() {
  const password = passwordInput.value;
  if (!password) return;

  let copySuccess = false;

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(password);
      copySuccess = true;
    } else {
      // Fallback for older browsers or restricted iframe contexts
      passwordInput.select();
      passwordInput.setSelectionRange(0, 99999);
      copySuccess = document.execCommand("copy");
      window.getSelection()?.removeAllRanges();
    }
  } catch (err) {
    console.warn("Clipboard API failed, attempting fallback:", err);
    try {
      passwordInput.select();
      copySuccess = document.execCommand("copy");
      window.getSelection()?.removeAllRanges();
    } catch (fallbackErr) {
      console.error("Copy failed completely", fallbackErr);
    }
  }

  if (copySuccess) {
    showCopyFeedback();
  }
}

/**
 * Displays visual confirmation when password has been copied.
 */
function showCopyFeedback() {
  // Update secondary copy button text
  const originalBtnContent = copyBtn.innerHTML;
  copyBtn.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
    Copied!
  `;
  copyBtn.style.borderColor = "#10b981";
  copyBtn.style.color = "#10b981";

  // Update top icon button
  copyIconBtn.classList.add("copied");
  copyIconBtn.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
  `;

  // Show floating toast
  toast.classList.add("show");
  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    toast.classList.remove("show");
  }, 2200);

  // Reset copy buttons after 2 seconds
  setTimeout(() => {
    copyBtn.innerHTML = originalBtnContent;
    copyBtn.style.borderColor = "";
    copyBtn.style.color = "";
    copyIconBtn.classList.remove("copied");
    copyIconBtn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
        <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
      </svg>
    `;
  }, 2000);
}

// ==========================================
// 7. Slider & Preset Handling
// ==========================================

/**
 * Updates the slider track background fill dynamically
 */
function updateSliderTrack(val) {
  const min = parseInt(lengthSlider.min, 10);
  const max = parseInt(lengthSlider.max, 10);
  const percentage = ((val - min) / (max - min)) * 100;
  lengthSlider.style.background = `linear-gradient(to right, var(--accent-cyan) 0%, var(--accent-cyan) ${percentage}%, #1e293b ${percentage}%, #1e293b 100%)`;
}

/**
 * Synchronizes active state on preset length buttons
 */
function syncPresetButtons(length) {
  presetButtons.forEach(btn => {
    if (parseInt(btn.dataset.length, 10) === length) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });
}

function handleLengthChange(newVal) {
  const val = parseInt(newVal, 10);
  lengthSlider.value = val;
  lengthValue.textContent = val;
  updateSliderTrack(val);
  syncPresetButtons(val);
  generatePassword();
}

// ==========================================
// 8. Toggles & Selection Guard
// ==========================================

const allToggles = [toggleUppercase, toggleLowercase, toggleNumbers, toggleSymbols];

/**
 * Validates that at least one toggle remains checked.
 * If user attempts to uncheck the last remaining toggle,
 * prevent it and show feedback.
 */
function handleToggleChange(event) {
  const activeCount = allToggles.filter(t => t.checked).length;

  if (activeCount === 0) {
    // Re-check this toggle
    event.target.checked = true;
    
    // Show visual shake and warning
    const optionItem = event.target.closest(".option-item");
    if (optionItem) {
      optionItem.classList.add("shake");
      setTimeout(() => optionItem.classList.remove("shake"), 350);
    }
    
    warningToast.classList.add("visible");
    setTimeout(() => {
      warningToast.classList.remove("visible");
    }, 2500);
    return;
  }

  warningToast.classList.remove("visible");
  generatePassword();
}

// ==========================================
// 9. Event Listeners Setup
// ==========================================

// Length slider input (live scrubbing)
lengthSlider.addEventListener("input", (e) => {
  handleLengthChange(e.target.value);
});

// Preset buttons
presetButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    handleLengthChange(btn.dataset.length);
  });
});

// Toggle switches
allToggles.forEach(toggle => {
  toggle.addEventListener("change", handleToggleChange);
});

// Generate button with spin animation
function triggerGenerateWithSpin() {
  refreshBtn.classList.add("spinning");
  generatePassword();
  setTimeout(() => {
    refreshBtn.classList.remove("spinning");
  }, 400);
}

generateBtn.addEventListener("click", triggerGenerateWithSpin);
refreshBtn.addEventListener("click", triggerGenerateWithSpin);

// Copy buttons
copyBtn.addEventListener("click", copyPasswordToClipboard);
copyIconBtn.addEventListener("click", copyPasswordToClipboard);

// Click anywhere inside password field to select all
passwordInput.addEventListener("click", () => {
  passwordInput.select();
});

// Keyboard shortcut: Press Space or Enter to generate a new password if focused on page
document.addEventListener("keydown", (e) => {
  if (e.code === "Space" && e.target === document.body) {
    e.preventDefault();
    triggerGenerateWithSpin();
  }
});

// ==========================================
// 10. Initial App Initialization
// ==========================================
function init() {
  const initialLength = parseInt(lengthSlider.value, 10);
  lengthValue.textContent = initialLength;
  updateSliderTrack(initialLength);
  syncPresetButtons(initialLength);
  generatePassword();
}

// Run on page load
init();
