// main.js
document.addEventListener('DOMContentLoaded', () => {
  const passwordInput = document.getElementById('passwordInput');
  const checkBtn = document.getElementById('checkBtn');
  const checkPwnedBtn = document.getElementById('checkPwnedBtn');
  const resBox = document.getElementById('resultBox');
  const resLength = document.getElementById('resLength');
  const resEntropy = document.getElementById('resEntropy');
  const resRating = document.getElementById('resRating');
  const commonAlert = document.getElementById('commonAlert');
  const suggBox = document.getElementById('suggBox');
  const pwnedResult = document.getElementById('pwnedResult');
  const toggleShow = document.getElementById('toggleShow');

  // generator elements
  const genLength = document.getElementById('genLength');
  const genLenLabel = document.getElementById('genLenLabel');
  const genUpper = document.getElementById('genUpper');
  const genDigits = document.getElementById('genDigits');
  const genSymbols = document.getElementById('genSymbols');
  const generateBtn = document.getElementById('generateBtn');
  const generated = document.getElementById('generated');
  const copyBtn = document.getElementById('copyBtn');
  const useGeneratedBtn = document.getElementById('useGeneratedBtn');

  // Toggle show/hide password
  toggleShow.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
      passwordInput.type = 'text';
      toggleShow.textContent = 'Hide';
    } else {
      passwordInput.type = 'password';
      toggleShow.textContent = 'Show';
    }
  });

  // Show length label for generator
  genLenLabel.textContent = genLength.value;
  genLength.addEventListener('input', () => {
    genLenLabel.textContent = genLength.value;
  });

  // Debounced real-time analysis (every 400ms after typing)
  let debounceTimer = null;
  passwordInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      realtimeAnalyze(passwordInput.value);
    }, 400);
  });

  checkBtn.addEventListener('click', () => {
    realtimeAnalyze(passwordInput.value, true);
  });

  checkPwnedBtn.addEventListener('click', async () => {
    pwnedResult.textContent = '';
    const pwd = passwordInput.value;
    if (!pwd) {
      pwnedResult.textContent = 'Enter a password first.';
      return;
    }
    pwnedResult.textContent = 'Checking...';
    try {
      const resp = await fetch('/api/pwned', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({password: pwd})
      });
      const data = await resp.json();
      if (resp.ok) {
        const count = data.pwned_count;
        if (count === 0) {
          pwnedResult.innerHTML = '<span class="text-success">Not found in breaches (0)</span>';
        } else {
          pwnedResult.innerHTML = `<span class="text-danger">Found ${count.toLocaleString()} times in breaches</span>`;
        }
      } else {
        pwnedResult.innerHTML = `<span class="text-warning">Error: ${data.error || 'unknown'}</span>`;
      }
    } catch (e) {
      pwnedResult.innerHTML = '<span class="text-warning">Network error</span>';
    }
  });

  async function realtimeAnalyze(pwd, explicit=false) {
    if (!pwd && !explicit) {
      resBox.style.display = 'none';
      pwnedResult.textContent = '';
      return;
    }
    try {
      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({password: pwd})
      });
      if (!resp.ok) {
        throw new Error('server error');
      }
      const data = await resp.json();
      resLength.textContent = data.length;
      resEntropy.textContent = data.entropy;
      resRating.textContent = data.rating;
      commonAlert.style.display = data.is_common ? 'block' : 'none';

      if (Array.isArray(data.suggestions) && data.suggestions.length) {
        suggBox.innerHTML = '<div class="alert alert-warning"><strong>Suggestions:</strong><ul>' +
          data.suggestions.map(s => `<li>${escapeHtml(s)}</li>`).join('') +
          '</ul></div>';
      } else {
        suggBox.innerHTML = '<div class="alert alert-success">✅ Looks good — consider using a password manager for storage.</div>';
      }
      resBox.style.display = 'block';
      pwnedResult.textContent = '';
    } catch (e) {
      console.error(e);
    }
  }

  // Password generator
  generateBtn.addEventListener('click', async () => {
    const length = genLength.value;
    const params = new URLSearchParams({
      length: length,
      upper: genUpper.checked,
      digits: genDigits.checked,
      symbols: genSymbols.checked
    });
    try {
      const resp = await fetch('/api/generate?' + params.toString());
      const data = await resp.json();
      if (resp.ok && data.password) {
        generated.value = data.password;
      } else {
        generated.value = 'Error generating';
      }
    } catch (e) {
      generated.value = 'Network error';
    }
  });

  copyBtn.addEventListener('click', async () => {
    if (!generated.value) return;
    try {
      await navigator.clipboard.writeText(generated.value);
      copyBtn.textContent = 'Copied';
      setTimeout(()=> copyBtn.textContent = 'Copy', 1500);
    } catch (e) {
      copyBtn.textContent = 'Copy Failed';
    }
  });

  useGeneratedBtn.addEventListener('click', () => {
    if (!generated.value) return;
    passwordInput.value = generated.value;
    realtimeAnalyze(generated.value, true);
  });

  function escapeHtml(unsafe) {
    return unsafe
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }
});

