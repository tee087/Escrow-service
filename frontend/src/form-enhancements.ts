const secretNames = new Set(['password', 'confirm', 'pin', 'confirmPin']);
const apiUrl = import.meta.env.VITE_API_URL || '';
const nicknameTimers = new WeakMap<HTMLInputElement, number>();

function addVisibilityControl(input: HTMLInputElement) {
  if (input.dataset.visibilityReady === 'true') return;
  input.dataset.visibilityReady = 'true';
  const wrapper = document.createElement('div');
  wrapper.className = 'secret';
  input.parentNode?.insertBefore(wrapper, input);
  wrapper.appendChild(input);
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'eye';
  button.setAttribute('aria-label', `Show ${input.placeholder}`);
  button.textContent = '◉̸';
  button.addEventListener('click', () => {
    const visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    button.textContent = visible ? '◉̸' : '◉';
    button.setAttribute('aria-label', `${visible ? 'Show' : 'Hide'} ${input.placeholder}`);
  });
  wrapper.appendChild(button);
}

function enhanceSecrets() {
  document.querySelectorAll<HTMLInputElement>('input[name]').forEach(input => {
    if (secretNames.has(input.name)) addVisibilityControl(input);
  });
}

function nicknameStatus(input: HTMLInputElement) {
  let status = input.parentElement?.querySelector<HTMLElement>('.nickname-status');
  if (!status) {
    status = document.createElement('p');
    status.className = 'nickname-status';
    status.setAttribute('aria-live', 'polite');
    input.insertAdjacentElement('afterend', status);
  }
  return status;
}

document.addEventListener('input', event => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || input.name !== 'nickname') return;
  const status = nicknameStatus(input);
  const nickname = input.value.trim();
  const priorTimer = nicknameTimers.get(input);
  if (priorTimer) window.clearTimeout(priorTimer);
  if (nickname.length < 3) {
    status.textContent = 'Enter at least 3 characters.';
    status.className = 'nickname-status pending';
    return;
  }
  status.textContent = 'Checking nickname…';
  status.className = 'nickname-status pending';
  nicknameTimers.set(input, window.setTimeout(async () => {
    try {
      const response = await fetch(`${apiUrl}/api/auth/nickname-availability?nickname=${encodeURIComponent(nickname)}`);
      const result = await response.json() as { available: boolean; message: string };
      status.textContent = result.message;
      status.className = `nickname-status ${result.available ? 'available' : 'unavailable'}`;
    } catch {
      status.textContent = 'Nickname availability could not be checked. You can still continue.';
      status.className = 'nickname-status pending';
    }
  }, 450));
});

document.addEventListener('click', event => {
  const button = (event.target as Element).closest<HTMLButtonElement>('button');
  if (!button || button.disabled || button.type === 'button' || button.classList.contains('link') || button.closest('nav')) return;
  const label = button.textContent || 'Please wait';
  button.disabled = true;
  button.classList.add('button-loading');
  button.innerHTML = '<span class="spinner" aria-hidden="true"></span>Processing…';
  window.setTimeout(() => {
    if (!button.isConnected) return;
    button.disabled = false;
    button.classList.remove('button-loading');
    button.textContent = label;
  }, 15000);
}, true);

const observer = new MutationObserver(enhanceSecrets);
observer.observe(document.documentElement, { childList: true, subtree: true });
enhanceSecrets();
