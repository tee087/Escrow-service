const secretNames = new Set(['password', 'confirm', 'pin', 'confirmPin']);

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
