import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './form-enhancements.css';

const apiUrl = import.meta.env.VITE_API_URL || '';

async function api(path: string, options: RequestInit = {}) {
  const token = sessionStorage.getItem('cl-service-session');
  const response = await fetch(`${apiUrl}${path}`, {
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...(options.headers || {}) },
    ...options
  });
  const data = await response.json();
  if (data.sessionToken) sessionStorage.setItem('cl-service-session', data.sessionToken);
  if (path === '/api/auth/logout') sessionStorage.removeItem('cl-service-session');
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

function EyeIcon({ hidden }: { hidden: boolean }) {
  return hidden ? <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18M10.6 6.2A10.8 10.8 0 0 1 12 6c6 0 9.5 6 9.5 6a17.7 17.7 0 0 1-3.1 3.7M6.1 6.1A17 17 0 0 0 2.5 12S6 18 12 18c1.2 0 2.3-.2 3.3-.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg> : <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>;
}

function SecretField({ name, placeholder, pin = false }: { name: string; placeholder: string; pin?: boolean }) {
  const [hidden, setHidden] = useState(true);
  return <div className="secret"><input name={name} type={hidden ? 'password' : 'text'} inputMode={pin ? 'numeric' : undefined} pattern={pin ? '[0-9]{4}' : undefined} maxLength={pin ? 4 : undefined} placeholder={placeholder} required /><button className="eye" type="button" onClick={() => setHidden(value => !value)} aria-label={`${hidden ? 'Show' : 'Hide'} ${placeholder}`}><EyeIcon hidden={hidden} /></button></div>;
}

function LoadingButton({ children, loading, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { loading: boolean }) {
  return <button {...props} disabled={loading || props.disabled}>{loading ? <span className="button-loading"><span className="spinner" aria-hidden="true" />Processing…</span> : children}</button>;
}

function Auth({ onAuthenticated }: { onAuthenticated: () => Promise<void> }) {
  const [mode, setMode] = useState<'register' | 'login'>('register');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [nickname, setNickname] = useState('');
  const [nicknameStatus, setNicknameStatus] = useState<{ message: string; available?: boolean }>({ message: '' });

  useEffect(() => {
    if (mode !== 'register' || nickname.trim().length < 3) {
      setNicknameStatus(nickname ? { message: 'Enter at least 3 characters.' } : { message: '' });
      return;
    }
    const timer = window.setTimeout(async () => {
      try {
        const result = await api(`/api/auth/nickname-availability?nickname=${encodeURIComponent(nickname.trim())}`);
        setNicknameStatus(result);
      } catch {
        setNicknameStatus({ message: 'Nickname availability could not be checked.' });
      }
    }, 450);
    return () => window.clearTimeout(timer);
  }, [mode, nickname]);

  const downloadUrl = useMemo(() => codes ? URL.createObjectURL(new Blob([codes.join('\n')], { type: 'text/plain' })) : '', [codes]);
  useEffect(() => () => { if (downloadUrl) URL.revokeObjectURL(downloadUrl); }, [downloadUrl]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loading) return;
    setError('');
    const form = new FormData(event.currentTarget);
    try {
      setLoading(true);
      if (mode === 'login') {
        await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ nickname: form.get('nickname'), password: form.get('password') }) });
        await onAuthenticated();
        return;
      }
      if (form.get('password') !== form.get('confirm')) throw new Error('Passwords do not match.');
      if (form.get('pin') !== form.get('confirmPin')) throw new Error('PIN codes do not match.');
      const result = await api('/api/auth/register', { method: 'POST', body: JSON.stringify({ nickname: form.get('nickname'), password: form.get('password'), pin: form.get('pin'), acceptedTerms: form.get('terms') === 'on' }) });
      setCodes(result.recoveryCodes);
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function continueToApp() {
    if (!saved) return setError('Please confirm that you have securely saved your recovery codes.');
    setError(''); setLoading(true);
    try { await onAuthenticated(); } catch (reason) { setError((reason as Error).message); } finally { setLoading(false); }
  }

  if (codes) return <main className="auth"><h1>Account Recovery</h1><p>Save your recovery codes somewhere safe. They can be used to recover your account if you lose access.</p><pre>{codes.join('\n')}</pre><LoadingButton loading={false} type="button" onClick={() => navigator.clipboard.writeText(codes.join('\n'))}>Copy Recovery Codes</LoadingButton><a className="button" download="cl-service-recovery-codes.txt" href={downloadUrl}>Download Recovery Codes</a><label><input type="checkbox" checked={saved} onChange={event => setSaved(event.target.checked)} /> I have securely saved my recovery codes.</label><LoadingButton loading={loading} type="button" onClick={continueToApp}>Continue to CL-Service</LoadingButton>{error && <p className="error">{error}</p>}</main>;
  return <main className="auth"><h1>{mode === 'register' ? 'Registration' : 'Login'}</h1><p>{mode === 'register' ? 'Already have an account? ' : 'New here? '}<button className="link" type="button" onClick={() => { setMode(mode === 'register' ? 'login' : 'register'); setError(''); }}>{mode === 'register' ? 'Log in' : 'Register'}</button></p><form onSubmit={submit}><input name="nickname" placeholder="Nickname" value={nickname} onChange={event => setNickname(event.target.value)} required />{mode === 'register' && nicknameStatus.message && <p className={`nickname-status ${nicknameStatus.available === true ? 'available' : nicknameStatus.available === false ? 'unavailable' : 'pending'}`}>{nicknameStatus.message}</p>}<SecretField name="password" placeholder="Password" />{mode === 'register' && <><SecretField name="confirm" placeholder="Confirm Password" /><h2>PIN Code</h2><p>Your PIN is required to confirm important actions.</p><SecretField name="pin" placeholder="4-digit PIN" pin /><SecretField name="confirmPin" placeholder="Confirm PIN" pin /><label><input name="terms" type="checkbox" /> I agree to the Terms of Service.</label></>}<LoadingButton loading={loading}>{mode === 'register' ? 'Next' : 'Login'}</LoadingButton></form>{error && <p className="error">{error}</p>}</main>;
}

function App() {
  const [profile, setProfile] = useState<any>(null);
  const [listings, setListings] = useState<any[]>([]);
  const [view, setView] = useState('Home');
  const [error, setError] = useState('');
  const loadProfile = async () => { const result = await api('/api/profile'); setProfile(result); };
  useEffect(() => { loadProfile().catch(() => undefined); api('/api/listings').then(setListings).catch(reason => setError(reason.message)); }, []);
  if (!profile) return <Auth onAuthenticated={loadProfile} />;
  return <main><header><span>Menu</span><strong>CL-Service</strong><span>Alerts</span></header>{view === 'Home' && <section><h1>Welcome, {profile.nickname}</h1><p className="muted">A secure marketplace for escrow-protected transactions.</p><div className="actions"><button onClick={() => setView('Catalog')}>Browse Catalog</button><button onClick={() => setView('Deals')}>View Deals</button></div><h2>Recent listings</h2>{listings.slice(0, 3).map(listing => <article key={listing.id}><b>{listing.title}</b><p>{listing.currency} {listing.price} · {listing.seller.nickname}</p></article>)}</section>}{view === 'Catalog' && <section><h1>Catalog</h1>{listings.length ? listings.map(listing => <article key={listing.id}><b>{listing.title}</b><p>{listing.description}</p></article>) : <p>No listings found.</p>}</section>}{view === 'Deals' && <section><h1>Deals</h1><p>No active deals.</p></section>}{view === 'Profile' && <section><h1>Profile</h1><p>{profile.nickname}</p><LoadingButton loading={false} onClick={async () => { await api('/api/auth/logout', { method: 'POST' }); setProfile(null); }}>Logout</LoadingButton></section>}<nav>{['Home', 'Catalog', 'Deals', 'Profile'].map(item => <button className={view === item ? 'active' : ''} onClick={() => setView(item)} key={item}>{item}</button>)}</nav>{error && <p className="error">{error}</p>}</main>;
}

createRoot(document.getElementById('root')!).render(<App />);
