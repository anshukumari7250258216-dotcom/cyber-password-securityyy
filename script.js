/**
 * ==============================================================================
 * CYBERSHIELD // AUTHGUARD - JAVASCRIPT CORE ENGINE
 * Author: BCA 2nd Year Cybersecurity Project
 * Purpose: Client-Side Password Strength Heuristics, Shannon Entropy Calculator,
 *          and Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).
 * 
 * Standards & Design Principles:
 * - Zero-Knowledge Architecture (No backend, no fetch, no localStorage, no cookies).
 * - NIST SP 800-63B guidelines alignment.
 * - Hardware entropy seeded via Web Cryptography API (`crypto.getRandomValues`).
 * - Unbiased Fisher-Yates character shuffling.
 * ==============================================================================
 */

'use strict';

// Wrap everything in an IIFE to keep global scope completely clean
(function () {

  /* --------------------------------------------------------------------------
     1. CONSTANTS & COMMON COMPROMISED PATTERNS (EDUCATIONAL DATABASE)
     -------------------------------------------------------------------------- */
  
  // High-frequency compromised passwords & common dictionary patterns
  const COMMON_DICTIONARY_WORDS = new Set([
    'password', 'password1', '123456', '12345678', '123456789', '12345',
    'qwerty', '111111', '123123', 'admin', 'welcome', 'login', 'football',
    'monkey', 'letmein', 'access', 'iloveyou', 'starwars', 'dragon',
    'master', 'sunshine', 'princess', 'solo', 'shadow', 'trustno1',
    'pass123', 'root', 'security', 'cyber', 'computer', 'superman',
    'batman', 'system', 'default', 'test', 'tester', 'guest', 'hunter2',
    'charlie', 'jordan', 'michael', 'jessica', 'ashley', 'daniel'
  ]);

  // Common keyboard sequence patterns
  const KEYBOARD_SEQUENCES = [
    'qwerty', 'asdfgh', 'zxcvbn', '123456', '234567', '345678', '456789',
    'abcdef', 'bcdefg', 'cdefgh', 'defghi', 'efghij', 'fghijk', 'ghijkl',
    '098765', '987654', '876543', '765432', '654321', '543210',
    'qwertz', 'azerty'
  ];

  // Character sets for generator
  const CHAR_SETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+~|}{[]:;?><,./-='
  };

  // Ambiguous characters that look visually similar
  const AMBIGUOUS_CHARS = new Set(['i', 'I', 'l', '1', 'L', 'o', '0', 'O']);

  // Memorable word pool for passphrase preset
  const PASSPHRASE_WORDS = [
    'cyber', 'shield', 'quantum', 'cipher', 'nexus', 'matrix', 'beacon',
    'vector', 'plasma', 'vortex', 'cobalt', 'crypto', 'tunnel', 'buffer',
    'kernel', 'socket', 'zenith', 'pulsar', 'aurora', 'vertex', 'packet',
    'anchor', 'binary', 'sensor', 'neuron', 'dynamo', 'fossil', 'beacon',
    'shadow', 'glitch', 'solace', 'carbon', 'photon', 'atomic', 'galaxy'
  ];

  // Theoretical hash rate for offline GPU brute-force calculation
  // 100 Billion hashes/sec is typical for a 8x modern GPU rig attacking fast hashes (e.g., MD5/NTLM)
  const ATTACK_HASHES_PER_SECOND = 100_000_000_000;

  /* --------------------------------------------------------------------------
     2. DOM ELEMENT REFERENCES
     -------------------------------------------------------------------------- */
  const dom = {
    // Nav & Mobile Drawer
    mobileMenuBtn: document.getElementById('mobile-menu-btn'),
    mobileNav: document.getElementById('mobile-nav'),
    navLinks: document.querySelectorAll('.nav-link, .mobile-nav-link'),

    // Password Input & Actions
    passwordInput: document.getElementById('password-input'),
    toggleVisibilityBtn: document.getElementById('toggle-visibility-btn'),
    eyeIcon: document.getElementById('eye-icon'),
    eyeOffIcon: document.getElementById('eye-off-icon'),
    clearInputBtn: document.getElementById('clear-input-btn'),
    charCounter: document.getElementById('char-counter'),

    // Strength Meter & Badges
    strengthMeter: document.getElementById('strength-meter'),
    meterFill: document.getElementById('meter-fill'),
    strengthBadge: document.getElementById('strength-badge'),

    // Telemetry Cards
    entropyValue: document.getElementById('entropy-value'),
    entropyEval: document.getElementById('entropy-eval'),
    crackTimeVal: document.getElementById('crack-time-val'),
    poolSizeVal: document.getElementById('pool-size-val'),
    poolTypesVal: document.getElementById('pool-types-val'),
    penaltyValue: document.getElementById('penalty-value'),
    penaltyDesc: document.getElementById('penalty-desc'),

    // Feedback & Suggestions
    suggestionsList: document.getElementById('suggestions-list'),
    feedbackTitle: document.getElementById('feedback-title'),
    feedbackIcon: document.getElementById('feedback-icon'),

    // Security Checklist Items
    checklistItems: document.querySelectorAll('.check-item'),
    checklistCounter: document.getElementById('checklist-counter'),
    fillWithGeneratedBtn: document.getElementById('fill-with-generated-btn'),

    // Generator Controls
    generatedPasswordText: document.getElementById('generated-password-text'),
    copyPasswordBtn: document.getElementById('copy-password-btn'),
    copyBtnLabel: document.getElementById('copy-btn-label'),
    regenerateBtn: document.getElementById('regenerate-btn'),
    copyFeedbackToast: document.getElementById('copy-feedback-toast'),
    lengthSlider: document.getElementById('length-slider'),
    lengthDisplay: document.getElementById('length-display'),
    optUppercase: document.getElementById('opt-uppercase'),
    optLowercase: document.getElementById('opt-lowercase'),
    optNumbers: document.getElementById('opt-numbers'),
    optSymbols: document.getElementById('opt-symbols'),
    optAmbiguous: document.getElementById('opt-ambiguous'),
    generatorErrorMsg: document.getElementById('generator-error-msg'),
    triggerGenerateBtn: document.getElementById('trigger-generate-btn'),
    testInAnalyzerBtn: document.getElementById('test-in-analyzer-btn'),
    presetButtons: document.querySelectorAll('.preset-btn'),

    // Dynamic Year in Footer
    currentYear: document.getElementById('current-year')
  };

  // Toast timer reference
  let toastTimeout = null;

  /* --------------------------------------------------------------------------
     3. INITIALIZATION & LIFECYCLE
     -------------------------------------------------------------------------- */
  function init() {
    // Set dynamic copyright year
    if (dom.currentYear) {
      dom.currentYear.textContent = new Date().getFullYear();
    }

    // Attach event listeners
    bindEvents();

    // Generate an initial safe demo password in the generator box
    generatePassword();

    // Reset analyzer to initial zero-state
    updateAnalyzer('');
  }

  /* --------------------------------------------------------------------------
     4. EVENT BINDINGS
     -------------------------------------------------------------------------- */
  function bindEvents() {
    // Mobile navigation toggle
    if (dom.mobileMenuBtn && dom.mobileNav) {
      dom.mobileMenuBtn.addEventListener('click', toggleMobileMenu);
    }

    // Close mobile menu when a link is clicked
    dom.navLinks.forEach(link => {
      link.addEventListener('click', () => {
        if (dom.mobileNav && dom.mobileNav.classList.contains('open')) {
          toggleMobileMenu();
        }
      });
    });

    // Password input listener for real-time analysis
    if (dom.passwordInput) {
      dom.passwordInput.addEventListener('input', (e) => {
        updateAnalyzer(e.target.value);
      });

      // Clear button
      if (dom.clearInputBtn) {
        dom.clearInputBtn.addEventListener('click', () => {
          dom.passwordInput.value = '';
          dom.passwordInput.focus();
          updateAnalyzer('');
        });
      }

      // Show/Hide password toggle
      if (dom.toggleVisibilityBtn) {
        dom.toggleVisibilityBtn.addEventListener('click', togglePasswordVisibility);
      }
    }

    // Generator Slider input listener
    if (dom.lengthSlider && dom.lengthDisplay) {
      dom.lengthSlider.addEventListener('input', (e) => {
        dom.lengthDisplay.textContent = e.target.value;
        generatePassword();
      });
    }

    // Generator Checkbox change listeners
    const checkboxes = [
      dom.optUppercase,
      dom.optLowercase,
      dom.optNumbers,
      dom.optSymbols,
      dom.optAmbiguous
    ];
    checkboxes.forEach(cb => {
      if (cb) {
        cb.addEventListener('change', () => {
          generatePassword();
        });
      }
    });

    // Preset button click listeners
    dom.presetButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        dom.presetButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        applyPreset(btn.dataset.preset);
      });
    });

    // Generator main trigger button
    if (dom.triggerGenerateBtn) {
      dom.triggerGenerateBtn.addEventListener('click', () => {
        generatePassword();
      });
    }

    // Refresh icon button
    if (dom.regenerateBtn) {
      dom.regenerateBtn.addEventListener('click', () => {
        // Visual spin effect
        const icon = document.getElementById('refresh-icon');
        if (icon) {
          icon.style.transform = 'rotate(360deg)';
          icon.style.transition = 'transform 0.4s ease';
          setTimeout(() => {
            icon.style.transform = '';
            icon.style.transition = '';
          }, 400);
        }
        generatePassword();
      });
    }

    // Copy button listener
    if (dom.copyPasswordBtn) {
      dom.copyPasswordBtn.addEventListener('click', copyPasswordToClipboard);
    }

    // Transfer generated password into analyzer
    if (dom.testInAnalyzerBtn) {
      dom.testInAnalyzerBtn.addEventListener('click', transferToAnalyzer);
    }

    // Checklist button to auto-fill generated password
    if (dom.fillWithGeneratedBtn) {
      dom.fillWithGeneratedBtn.addEventListener('click', () => {
        generatePassword();
        transferToAnalyzer();
      });
    }
  }

  /* --------------------------------------------------------------------------
     5. NAVIGATION & UI HELPERS
     -------------------------------------------------------------------------- */
  function toggleMobileMenu() {
    const isOpen = dom.mobileNav.classList.toggle('open');
    dom.mobileMenuBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    dom.mobileNav.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
  }

  function togglePasswordVisibility() {
    const isPassword = dom.passwordInput.type === 'password';
    dom.passwordInput.type = isPassword ? 'text' : 'password';

    if (isPassword) {
      dom.eyeIcon.classList.add('hidden');
      dom.eyeOffIcon.classList.remove('hidden');
      dom.toggleVisibilityBtn.setAttribute('aria-label', 'Hide password (mask as dots)');
      dom.toggleVisibilityBtn.setAttribute('title', 'Hide password');
    } else {
      dom.eyeIcon.classList.remove('hidden');
      dom.eyeOffIcon.classList.add('hidden');
      dom.toggleVisibilityBtn.setAttribute('aria-label', 'Show password as plain text');
      dom.toggleVisibilityBtn.setAttribute('title', 'Show password');
    }
  }

  /* --------------------------------------------------------------------------
     6. PASSWORD SECURITY EVALUATION & SHANNON ENTROPY ALGORITHM
     -------------------------------------------------------------------------- */
  
  /**
   * Analyzes the given password string and computes Shannon Entropy,
   * brute-force resistance time, vulnerabilities, and checklist status.
   * 
   * @param {string} password - The plain-text password to evaluate in RAM.
   */
  function updateAnalyzer(password) {
    const length = password.length;

    // Update length counter text
    if (dom.charCounter) {
      dom.charCounter.textContent = `${length} ${length === 1 ? 'character' : 'characters'}`;
    }

    // Handle Empty Input State
    if (!password || length === 0) {
      renderEmptyState();
      return;
    }

    // 1. Detect Character Categories & Pool Size (R)
    let hasLower = false;
    let hasUpper = false;
    let hasNumber = false;
    let hasSymbol = false;

    let poolSize = 0;
    let categoryCount = 0;

    if (/[a-z]/.test(password)) {
      hasLower = true;
      poolSize += 26;
      categoryCount++;
    }
    if (/[A-Z]/.test(password)) {
      hasUpper = true;
      poolSize += 26;
      categoryCount++;
    }
    if (/[0-9]/.test(password)) {
      hasNumber = true;
      poolSize += 10;
      categoryCount++;
    }
    if (/[^a-zA-Z0-9]/.test(password)) {
      hasSymbol = true;
      poolSize += 33; // Standard printable ASCII special symbols
      categoryCount++;
    }

    // Minimum fallback pool size if user entered unusual unicode
    if (poolSize === 0 && length > 0) poolSize = 26;

    // 2. Pattern Detection: Repetitions & Sequences
    const repetitionAnalysis = detectConsecutiveRepetitions(password);
    const sequenceAnalysis = detectKeyboardSequences(password);
    const dictionaryMatch = checkCommonDictionary(password);

    // 3. Mathematical Shannon / Combinatorial Entropy Calculation:
    // Base formula: Entropy (E) = Length * log2(PoolSize)
    let rawEntropy = length * (Math.log(poolSize) / Math.LN2);

    // Apply heuristic deductions for structural weaknesses
    let entropyPenalty = 0;
    let penaltyReason = 'None';

    if (dictionaryMatch) {
      entropyPenalty += 35;
      penaltyReason = 'Known dictionary leak match';
    } else if (sequenceAnalysis.detected) {
      entropyPenalty += 18;
      penaltyReason = `Sequence walk ('${sequenceAnalysis.matched}')`;
    } else if (repetitionAnalysis.detected) {
      entropyPenalty += 14;
      penaltyReason = 'Repeated char clusters';
    } else if (categoryCount === 1 && length > 6) {
      entropyPenalty += 10;
      penaltyReason = 'Single character class only';
    }

    // Effective entropy after deduction, bounded >= 0
    let effectiveEntropy = Math.max(0, rawEntropy - entropyPenalty);

    // If password is under 6 characters, cap entropy to reflect brute-force vulnerability
    if (length < 6) {
      effectiveEntropy = Math.min(effectiveEntropy, 22);
    }

    // 4. Calculate Brute-Force Crack Time Estimate
    const crackTimeData = calculateCrackTime(effectiveEntropy);

    // 5. Determine 5-Tier Strength Classification & Meter Percentage
    const tierData = evaluateStrengthTier(effectiveEntropy, length, dictionaryMatch);

    // 6. Update UI Components
    renderTelemetry({
      length,
      effectiveEntropy,
      poolSize,
      categoryCount,
      crackTimeData,
      penaltyReason,
      entropyPenalty
    });

    renderStrengthMeter(tierData);
    renderChecklist({
      length,
      hasUpper,
      hasLower,
      hasNumber,
      hasSymbol,
      repetitionDetected: repetitionAnalysis.detected,
      dictionaryDetected: dictionaryMatch || sequenceAnalysis.detected
    });

    renderSuggestions({
      length,
      hasUpper,
      hasLower,
      hasNumber,
      hasSymbol,
      repetitionAnalysis,
      sequenceAnalysis,
      dictionaryMatch,
      effectiveEntropy,
      tier: tierData.name
    });
  }

  /**
   * Resets analyzer UI elements to their baseline empty states.
   */
  function renderEmptyState() {
    // Meter
    if (dom.meterFill) {
      dom.meterFill.style.width = '0%';
      dom.meterFill.className = 'meter-fill tier-empty';
    }
    if (dom.strengthMeter) {
      dom.strengthMeter.setAttribute('aria-valuenow', '0');
    }
    if (dom.strengthBadge) {
      dom.strengthBadge.textContent = 'Awaiting Input';
      dom.strengthBadge.className = 'strength-badge tier-empty';
    }

    // Telemetry
    if (dom.entropyValue) dom.entropyValue.textContent = '0.0';
    if (dom.entropyEval) dom.entropyEval.textContent = 'No input detected';
    if (dom.crackTimeVal) dom.crackTimeVal.textContent = 'Instant';
    if (dom.poolSizeVal) dom.poolSizeVal.textContent = '0';
    if (dom.poolTypesVal) dom.poolTypesVal.textContent = '0 categories active';
    if (dom.penaltyValue) dom.penaltyValue.textContent = 'None';
    if (dom.penaltyDesc) dom.penaltyDesc.textContent = 'Clean character distribution';

    // Checklist reset
    dom.checklistItems.forEach(item => {
      item.classList.remove('passed');
      const icon = item.querySelector('.check-icon');
      if (icon) icon.textContent = '✕';
    });
    if (dom.checklistCounter) dom.checklistCounter.textContent = '0 / 7 Met';

    // Suggestions default
    if (dom.suggestionsList) {
      dom.suggestionsList.innerHTML = `
        <li class="suggestion-item">Start typing a password to view automated cybersecurity recommendations.</li>
      `;
    }
    if (dom.feedbackTitle) dom.feedbackTitle.textContent = 'Educational Security Guidance';
    if (dom.feedbackIcon) dom.feedbackIcon.textContent = '💡';
  }

  /**
   * Identifies consecutive repetitions like 'aaa', '1111', etc.
   */
  function detectConsecutiveRepetitions(str) {
    const match = /(.)\1{2,}/i.exec(str);
    return {
      detected: !!match,
      char: match ? match[1] : null
    };
  }

  /**
   * Checks for obvious sequential keyboard walks or alphabetical runs.
   */
  function detectKeyboardSequences(str) {
    const lower = str.toLowerCase();
    for (const seq of KEYBOARD_SEQUENCES) {
      if (lower.includes(seq)) {
        return { detected: true, matched: seq };
      }
      // Check reverse
      const rev = seq.split('').reverse().join('');
      if (lower.includes(rev)) {
        return { detected: true, matched: rev };
      }
    }
    return { detected: false, matched: '' };
  }

  /**
   * Checks for known common passwords, dictionary entries, or simple leetspeak variants.
   */
  function checkCommonDictionary(str) {
    const lower = str.toLowerCase();

    // Direct check
    if (COMMON_DICTIONARY_WORDS.has(lower)) {
      return true;
    }

    // Normalize basic leetspeak: @ -> a, 0 -> o, 1 -> l, 3 -> e, $ -> s, 5 -> s
    const normalized = lower
      .replace(/@/g, 'a')
      .replace(/0/g, 'o')
      .replace(/1/g, 'i')
      .replace(/3/g, 'e')
      .replace(/[$5]/g, 's')
      .replace(/!/g, 'i');

    if (COMMON_DICTIONARY_WORDS.has(normalized)) {
      return true;
    }

    return false;
  }

  /**
   * Estimates offline brute-force cracking duration based on effective entropy.
   */
  function calculateCrackTime(entropy) {
    // Total search space = 2^entropy. On average, key is found at 50% search space = 2^(entropy - 1)
    if (entropy < 1) {
      return { readable: 'Instant (< 1 ms)', seconds: 0 };
    }

    // Number of guesses on average
    const averageGuesses = Math.pow(2, Math.max(0, entropy - 1));
    const seconds = averageGuesses / ATTACK_HASHES_PER_SECOND;

    return {
      seconds,
      readable: formatSecondsToHumanReadable(seconds)
    };
  }

  /**
   * Converts raw seconds into human-digestible educational duration.
   */
  function formatSecondsToHumanReadable(seconds) {
    if (seconds < 0.001) return 'Instant (< 1 ms)';
    if (seconds < 1) return 'Less than a second';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    
    const minutes = seconds / 60;
    if (minutes < 60) return `${Math.round(minutes)} minutes`;

    const hours = minutes / 60;
    if (hours < 24) return `${Math.round(hours)} hours`;

    const days = hours / 24;
    if (days < 365) return `${Math.round(days)} days`;

    const years = days / 365.25;
    if (years < 100) return `${Math.round(years)} years`;
    if (years < 10_000) return `${Math.round(years).toLocaleString()} years`;
    if (years < 1_000_000) return `${(years / 1_000).toFixed(1)} thousand years`;
    if (years < 1_000_000_000) return `${(years / 1_000_000).toFixed(1)} million years`;
    if (years < 1_000_000_000_000) return `${(years / 1_000_000_000).toFixed(1)} billion years`;

    return 'Trillions of years (Impractical)';
  }

  /**
   * Evaluates the 5-tier classification score.
   */
  function evaluateStrengthTier(entropy, length, isDictionary) {
    if (isDictionary || length < 6 || entropy < 28) {
      return {
        name: 'Very Weak',
        cssClass: 'tier-very-weak',
        percentage: Math.min(20, Math.max(10, length * 3)),
        badgeColor: 'tier-very-weak'
      };
    }
    if (entropy < 45 || length < 8) {
      return {
        name: 'Weak',
        cssClass: 'tier-weak',
        percentage: 38,
        badgeColor: 'tier-weak'
      };
    }
    if (entropy < 62 || length < 12) {
      return {
        name: 'Medium',
        cssClass: 'tier-medium',
        percentage: 60,
        badgeColor: 'tier-medium'
      };
    }
    if (entropy < 84 || length < 16) {
      return {
        name: 'Strong',
        cssClass: 'tier-strong',
        percentage: 82,
        badgeColor: 'tier-strong'
      };
    }
    return {
      name: 'Very Strong',
      cssClass: 'tier-very-strong',
      percentage: 100,
      badgeColor: 'tier-very-strong'
    };
  }

  /* --------------------------------------------------------------------------
     7. UI RENDERING SUBROUTINES
     -------------------------------------------------------------------------- */
  
  function renderStrengthMeter(tierData) {
    if (dom.meterFill) {
      dom.meterFill.style.width = `${tierData.percentage}%`;
      dom.meterFill.className = `meter-fill ${tierData.cssClass}`;
    }
    if (dom.strengthMeter) {
      dom.strengthMeter.setAttribute('aria-valuenow', tierData.percentage.toString());
    }
    if (dom.strengthBadge) {
      dom.strengthBadge.textContent = tierData.name;
      dom.strengthBadge.className = `strength-badge ${tierData.badgeColor}`;
    }
  }

  function renderTelemetry(data) {
    // 1. Entropy
    if (dom.entropyValue) {
      dom.entropyValue.textContent = data.effectiveEntropy.toFixed(1);
    }
    if (dom.entropyEval) {
      if (data.effectiveEntropy < 35) {
        dom.entropyEval.textContent = 'Dangerously low search space';
      } else if (data.effectiveEntropy < 55) {
        dom.entropyEval.textContent = 'Moderate security boundary';
      } else if (data.effectiveEntropy < 80) {
        dom.entropyEval.textContent = 'Robust against offline attacks';
      } else {
        dom.entropyEval.textContent = 'Cryptographic-grade resistance';
      }
    }

    // 2. Crack Time
    if (dom.crackTimeVal) {
      dom.crackTimeVal.textContent = data.crackTimeData.readable;
    }

    // 3. Pool Size
    if (dom.poolSizeVal) {
      dom.poolSizeVal.textContent = data.poolSize.toString();
    }
    if (dom.poolTypesVal) {
      dom.poolTypesVal.textContent = `${data.categoryCount} of 4 categories active`;
    }

    // 4. Vulnerabilities
    if (dom.penaltyValue) {
      dom.penaltyValue.textContent = data.entropyPenalty > 0 ? `-${data.entropyPenalty} bits` : '0 bits';
    }
    if (dom.penaltyDesc) {
      dom.penaltyDesc.textContent = data.penaltyReason;
    }
  }

  function renderChecklist(status) {
    let passedCount = 0;

    const rules = {
      length: status.length >= 12,
      uppercase: status.hasUpper,
      lowercase: status.hasLower,
      numbers: status.hasNumber,
      symbols: status.hasSymbol,
      repetition: !status.repetitionDetected,
      dictionary: !status.dictionaryDetected
    };

    dom.checklistItems.forEach(item => {
      const ruleKey = item.dataset.rule;
      const passed = !!rules[ruleKey];
      const icon = item.querySelector('.check-icon');

      if (passed) {
        item.classList.add('passed');
        if (icon) icon.textContent = '✓';
        passedCount++;
      } else {
        item.classList.remove('passed');
        if (icon) icon.textContent = '✕';
      }
    });

    if (dom.checklistCounter) {
      dom.checklistCounter.textContent = `${passedCount} / 7 Met`;
      if (passedCount === 7) {
        dom.checklistCounter.style.color = '#10b981';
      } else if (passedCount >= 4) {
        dom.checklistCounter.style.color = '#38bdf8';
      } else {
        dom.checklistCounter.style.color = '#f43f5e';
      }
    }
  }

  function renderSuggestions(analysis) {
    const suggestions = [];

    if (analysis.dictionaryMatch) {
      suggestions.push('⚠️ This password appears in common breach lists or dictionary terms. Change it immediately.');
    }

    if (analysis.sequenceAnalysis.detected) {
      suggestions.push(`Avoid sequential keyboard walks like '${analysis.sequenceAnalysis.matched}', which automated crackers check first.`);
    }

    if (analysis.repetitionAnalysis.detected) {
      suggestions.push('Eliminate repeating characters (e.g. "aaa" or "111") that collapse theoretical entropy.');
    }

    if (analysis.length < 12) {
      suggestions.push(`Extend password length by at least ${12 - analysis.length} more characters. Length provides exponential entropy growth.`);
    }

    if (!analysis.hasUpper || !analysis.hasLower) {
      suggestions.push('Mix both UPPERCASE and lowercase letters to increase pool size by 26 characters.');
    }

    if (!analysis.hasNumber) {
      suggestions.push('Insert numeric digits (0-9) to neutralize purely alphabetical wordlist attacks.');
    }

    if (!analysis.hasSymbol) {
      suggestions.push('Include special symbols (!@#$...) to maximize search space to 94+ printable ASCII symbols.');
    }

    if (suggestions.length === 0) {
      suggestions.push('🌟 Excellent security profile! This password exhibits high entropy and resists dictionary attacks.');
      suggestions.push('Store it safely in an encrypted password manager rather than reusing it across other websites.');
    }

    if (dom.suggestionsList) {
      dom.suggestionsList.innerHTML = suggestions
        .map(tip => `<li class="suggestion-item">${tip}</li>`)
        .join('');
    }

    if (dom.feedbackTitle) {
      dom.feedbackTitle.textContent = analysis.tier === 'Very Strong' || analysis.tier === 'Strong'
        ? 'Defensive Resilience Verified'
        : 'Actionable Security Recommendations';
    }

    if (dom.feedbackIcon) {
      dom.feedbackIcon.textContent = analysis.tier === 'Very Strong' || analysis.tier === 'Strong' ? '🛡️' : '💡';
    }
  }

  /* --------------------------------------------------------------------------
     8. CRYPTOGRAPHICALLY SECURE PASSWORD GENERATOR (CSPRNG)
     -------------------------------------------------------------------------- */
  
  /**
   * Generates a cryptographically strong, mathematically unbiased password
   * using the Web Cryptography API (`crypto.getRandomValues`).
   */
  function generatePassword() {
    const length = parseInt(dom.lengthSlider.value, 10) || 18;

    // Determine active character sets
    const useUpper = dom.optUppercase.checked;
    const useLower = dom.optLowercase.checked;
    const useNumbers = dom.optNumbers.checked;
    const useSymbols = dom.optSymbols.checked;
    const excludeAmbiguous = dom.optAmbiguous.checked;

    // Validation: At least one set must be selected
    if (!useUpper && !useLower && !useNumbers && !useSymbols) {
      if (dom.generatorErrorMsg) dom.generatorErrorMsg.classList.remove('hidden');
      if (dom.generatedPasswordText) dom.generatedPasswordText.textContent = 'Select at least 1 option';
      return;
    } else {
      if (dom.generatorErrorMsg) dom.generatorErrorMsg.classList.add('hidden');
    }

    let activePool = '';
    const guaranteedChars = [];

    // Filter sets for ambiguous characters if option active
    function filterChars(charString) {
      if (!excludeAmbiguous) return charString;
      return charString
        .split('')
        .filter(c => !AMBIGUOUS_CHARS.has(c))
        .join('');
    }

    const upperSet = filterChars(CHAR_SETS.uppercase);
    const lowerSet = filterChars(CHAR_SETS.lowercase);
    const numSet = filterChars(CHAR_SETS.numbers);
    const symSet = filterChars(CHAR_SETS.symbols);

    // Ensure at least one character from each enabled set is included
    if (useUpper && upperSet.length > 0) {
      activePool += upperSet;
      guaranteedChars.push(getRandomCharFromString(upperSet));
    }
    if (useLower && lowerSet.length > 0) {
      activePool += lowerSet;
      guaranteedChars.push(getRandomCharFromString(lowerSet));
    }
    if (useNumbers && numSet.length > 0) {
      activePool += numSet;
      guaranteedChars.push(getRandomCharFromString(numSet));
    }
    if (useSymbols && symSet.length > 0) {
      activePool += symSet;
      guaranteedChars.push(getRandomCharFromString(symSet));
    }

    if (activePool.length === 0) {
      if (dom.generatedPasswordText) dom.generatedPasswordText.textContent = 'Empty character pool';
      return;
    }

    // Fill the remainder of the length
    const passwordChars = [...guaranteedChars];
    const remainingCount = Math.max(0, length - guaranteedChars.length);

    for (let i = 0; i < remainingCount; i++) {
      passwordChars.push(getRandomCharFromString(activePool));
    }

    // Unbiased Fisher-Yates Shuffle using crypto.getRandomValues
    unbiasedShuffle(passwordChars);

    const finalPassword = passwordChars.slice(0, length).join('');

    if (dom.generatedPasswordText) {
      dom.generatedPasswordText.textContent = finalPassword;
    }
  }

  /**
   * Generates an unbiased random character from a given string using CSPRNG.
   * Eliminates modulo bias by rejecting values above the largest multiple.
   */
  function getRandomCharFromString(str) {
    const poolLength = str.length;
    if (poolLength === 0) return '';

    // Modulo bias elimination limit
    // 32-bit unsigned integer max = 4,294,967,295
    const maxUint32 = 0xFFFFFFFF;
    const limit = maxUint32 - (maxUint32 % poolLength);

    const randomBuffer = new Uint32Array(1);

    while (true) {
      window.crypto.getRandomValues(randomBuffer);
      const randVal = randomBuffer[0];
      if (randVal < limit) {
        return str[randVal % poolLength];
      }
    }
  }

  /**
   * Cryptographic in-place Fisher-Yates array shuffle.
   */
  function unbiasedShuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
      // Pick random index from 0 to i
      const j = getRandomInt(0, i);
      const temp = array[i];
      array[i] = array[j];
      array[j] = temp;
    }
  }

  /**
   * Returns a cryptographically secure integer between min and max (inclusive).
   */
  function getRandomInt(min, max) {
    const range = max - min + 1;
    const maxUint32 = 0xFFFFFFFF;
    const limit = maxUint32 - (maxUint32 % range);
    const randomBuffer = new Uint32Array(1);

    while (true) {
      window.crypto.getRandomValues(randomBuffer);
      const val = randomBuffer[0];
      if (val < limit) {
        return min + (val % range);
      }
    }
  }

  /**
   * Generates a 4-word memorable passphrase with high entropy.
   */
  function generateMemorablePassphrase() {
    const wordCount = 4;
    const selectedWords = [];

    for (let i = 0; i < wordCount; i++) {
      const idx = getRandomInt(0, PASSPHRASE_WORDS.length - 1);
      selectedWords.push(PASSPHRASE_WORDS[idx]);
    }

    // Add a random 2-digit number and a symbol to satisfy legacy systems
    const randomNum = getRandomInt(10, 99);
    const symbols = '!@#$%^&*';
    const randomSymbol = symbols[getRandomInt(0, symbols.length - 1)];

    return `${selectedWords.join('-')}-${randomNum}${randomSymbol}`;
  }

  /**
   * Handles pre-configured generator profiles.
   */
  function applyPreset(presetType) {
    if (presetType === 'maximum') {
      dom.lengthSlider.value = 18;
      dom.lengthDisplay.textContent = '18';
      dom.optUppercase.checked = true;
      dom.optLowercase.checked = true;
      dom.optNumbers.checked = true;
      dom.optSymbols.checked = true;
      dom.optAmbiguous.checked = false;
      generatePassword();
    } else if (presetType === 'readable') {
      dom.lengthSlider.value = 16;
      dom.lengthDisplay.textContent = '16';
      dom.optUppercase.checked = true;
      dom.optLowercase.checked = true;
      dom.optNumbers.checked = true;
      dom.optSymbols.checked = false;
      dom.optAmbiguous.checked = true;
      generatePassword();
    } else if (presetType === 'pin') {
      dom.lengthSlider.value = 8;
      dom.lengthDisplay.textContent = '8';
      dom.optUppercase.checked = false;
      dom.optLowercase.checked = false;
      dom.optNumbers.checked = true;
      dom.optSymbols.checked = false;
      dom.optAmbiguous.checked = false;
      generatePassword();
    } else if (presetType === 'passphrase') {
      const passphrase = generateMemorablePassphrase();
      if (dom.generatedPasswordText) {
        dom.generatedPasswordText.textContent = passphrase;
      }
    }
  }

  /**
   * Secure Clipboard Copy Functionality.
   */
  function copyPasswordToClipboard() {
    const password = dom.generatedPasswordText.textContent;
    if (!password || password.startsWith('Select at least') || password.startsWith('Click Generate')) {
      return;
    }

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(password)
        .then(showCopyFeedback)
        .catch(fallbackClipboardCopy);
    } else {
      fallbackClipboardCopy();
    }
  }

  /**
   * Fallback copy mechanism for non-secure contexts or legacy environments.
   */
  function fallbackClipboardCopy() {
    const password = dom.generatedPasswordText.textContent;
    const tempTextArea = document.createElement('textarea');
    tempTextArea.value = password;
    tempTextArea.style.position = 'fixed';
    tempTextArea.style.left = '-9999px';
    tempTextArea.style.top = '0';
    document.body.appendChild(tempTextArea);
    tempTextArea.focus();
    tempTextArea.select();

    try {
      const successful = document.execCommand('copy');
      if (successful) showCopyFeedback();
    } catch (err) {
      // Inaudible failure fallback
    } finally {
      document.body.removeChild(tempTextArea);
    }
  }

  /**
   * Displays visual confirmation badge after copying.
   */
  function showCopyFeedback() {
    if (dom.copyBtnLabel) dom.copyBtnLabel.textContent = 'Copied!';
    if (dom.copyPasswordBtn) dom.copyPasswordBtn.style.background = '#10b981';

    if (dom.copyFeedbackToast) {
      dom.copyFeedbackToast.classList.remove('hidden');
    }

    if (toastTimeout) clearTimeout(toastTimeout);

    toastTimeout = setTimeout(() => {
      if (dom.copyBtnLabel) dom.copyBtnLabel.textContent = 'Copy';
      if (dom.copyPasswordBtn) dom.copyPasswordBtn.style.background = '';
      if (dom.copyFeedbackToast) dom.copyFeedbackToast.classList.add('hidden');
    }, 2200);
  }

  /**
   * Pushes the generated password directly into the strength analyzer.
   */
  function transferToAnalyzer() {
    const password = dom.generatedPasswordText.textContent;
    if (!password || password.startsWith('Select at least') || password.startsWith('Click Generate')) {
      return;
    }

    if (dom.passwordInput) {
      dom.passwordInput.value = password;
      dom.passwordInput.focus();
      updateAnalyzer(password);

      // Smooth scroll to analyzer card
      const analyzerSection = document.getElementById('analyzer');
      if (analyzerSection) {
        analyzerSection.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }

  /* --------------------------------------------------------------------------
     9. AUTO-RUN INITIALIZER
     -------------------------------------------------------------------------- */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
