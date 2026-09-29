const secretNames = new Set(['password', 'confirm', 'pin', 'confirmPin']);
import './form-enhancements.css';

const apiUrl = import.meta.env.VITE_API_URL || '';
const nicknameTimers = new WeakMap<HTMLInputElement, number>();
const eyeIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>';
const eyeOffIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18M10.6 6.2A10.8 10.8 0 0 1 12 6c6 0 9.5 6 9.5 6a17.7 17.7 0 0 1-3.1 3.7M6.1 6.1A17 17 0 0 0 2.5 12S6 18 12 18c1.2 0 2.3-.2 3.3-.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';

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
  button.innerHTML = eyeOffIcon;
  button.addEventListener('click', () => {
    const visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    button.innerHTML = visible ? eyeOffIcon : eyeIcon;
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
