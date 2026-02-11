(function () {
  const pwdInput = document.querySelector('#password');
  const meter = document.querySelector('#passwordMeter');
  if (pwdInput && meter) {
    pwdInput.addEventListener('input', () => {
      const value = pwdInput.value;
      const score = strengthScore(value);
      meter.value = score;
    });
  }

  function strengthScore(pwd) {
    let score = 0;
    if (pwd.length >= 8) score += 25;
    if (/[A-Z]/.test(pwd)) score += 25;
    if (/[a-z]/.test(pwd)) score += 15;
    if (/\d/.test(pwd)) score += 15;
    if (/[!@#$%^&*()_+\-]/.test(pwd)) score += 20;
    return Math.min(score, 100);
  }

  // Attach CSRF token to fetch calls (if any)
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
  if (csrfToken) {
    const _fetch = window.fetch;
    window.fetch = (resource, options = {}) => {
      options.headers = Object.assign({}, options.headers, { 'X-CSRFToken': csrfToken });
      return _fetch(resource, options);
    };
  }
})();
