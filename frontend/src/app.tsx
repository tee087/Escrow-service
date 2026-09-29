import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './form-enhancements.css';
import './dashboard.css';
import './navigation.css';
import './community-chat.css';
import { CommunityChat, NavigationDashboard } from './navigation-dashboard';

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

function Icon({ name }: { name: 'shield' | 'bell' | 'menu' | 'search' | 'tag' | 'home' | 'grid' | 'user' | 'arrow' | 'document' }) {
  const paths = { shield: <><path d="M12 3 20 6v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6l8-3Z" /><path d="M9 11V9.5a3 3 0 0 1 6 0V11" /><rect x="8" y="11" width="8" height="6" rx="1" /></>, bell: <><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" /><path d="M10 21h4" /></>, menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>, search: <><circle cx="11" cy="11" r="6" /><path d="m16 16 5 5" /></>, tag: <><path d="M20 13 13 20 4 11V4h7l9 9Z" /><circle cx="8.5" cy="8.5" r="1" /></>, home: <><path d="m3 11 9-8 9 8v9h-6v-6H9v6H3v-9Z" /></>, grid: <><rect x="4" y="4" width="6" height="6" rx="1" /><rect x="14" y="4" width="6" height="6" rx="1" /><rect x="4" y="14" width="6" height="6" rx="1" /><rect x="14" y="14" width="6" height="6" rx="1" /></>, user: <><circle cx="12" cy="8" r="4" /><path d="M4 21c.8-4 3.4-6 8-6s7.2 2 8 6" /></>, arrow: <path d="m9 5 7 7-7 7" />, document: <><path d="M7 3h8l3 3v15H7V3Z" /><path d="M10 11h5M10 15h5" /></> };
  return <svg className="icon" viewBox="0 0 24 24" aria-hidden="true">{paths[name]}</svg>;
}

function Dashboard({ profile, listings, view, setView, logout }: { profile: any; listings: any[]; view: string; setView: (view: string) => void; logout: () => Promise<void> }) {
  const displayName = profile.nickname.charAt(0).toUpperCase() + profile.nickname.slice(1);
  return <main className="dashboard"><header className="dash-header"><div className="brand-mark"><Icon name="shield" /></div><div><strong>CL-Service</strong><p>Safe trades <span>•</span> Trusted by many</p></div><div className="header-actions"><button aria-label="Notifications"><Icon name="bell" /><i /></button><button aria-label="Menu"><Icon name="menu" /></button></div></header>{view === 'Home' && <><section className="hero"><div><span>Welcome</span><h1>{displayName}</h1><p>A secure marketplace for escrow-protected transactions.</p></div><div className="hero-shield"><Icon name="shield" /></div></section><section className="quick-actions"><button className="catalog-action" onClick={() => setView('Catalog')}><span className="action-icon"><Icon name="search" /></span><span><b>Browse Catalog</b><small>Find verified deals</small></span><Icon name="arrow" /></button><button className="deals-action" onClick={() => setView('Deals')}><span className="action-icon"><Icon name="tag" /></span><span><b>View Deals</b><small>Latest offers & listings</small></span><Icon name="arrow" /></button></section><section className="recent"><div className="section-title"><h2>Recent Listings</h2><button onClick={() => setView('Catalog')}>View all <Icon name="arrow" /></button></div>{listings.length ? <div className="listing-grid">{listings.slice(0, 3).map(listing => <article key={listing.id}><b>{listing.title}</b><p>{listing.currency} {listing.price} · {listing.seller.nickname}</p></article>)}</div> : <div className="empty-listings"><span><Icon name="document" /></span><h3>No recent listings yet</h3><p>Browse our catalog or check back later for new deals.</p></div>}</section></>}{view === 'Catalog' && <section className="panel"><h1>Catalog</h1>{listings.length ? listings.map(listing => <article key={listing.id}><b>{listing.title}</b><p>{listing.description}</p></article>) : <p>No listings found.</p>}</section>}{view === 'Deals' && <section className="panel"><h1>Deals</h1><p>No active deals.</p></section>}{view === 'Profile' && <section className="panel profile-panel"><span className="profile-avatar">{displayName[0]}</span><h1>{displayName}</h1><p>Manage your CL-Service account and security settings.</p><LoadingButton loading={false} onClick={logout}>Logout</LoadingButton></section>}<nav className="bottom-nav">{([{ name: 'Home', icon: 'home' }, { name: 'Catalog', icon: 'grid' }, { name: 'Deals', icon: 'tag' }, { name: 'Profile', icon: 'user' }] as const).map(item => <button className={view === item.name ? 'active' : ''} onClick={() => setView(item.name)} key={item.name}><Icon name={item.icon} /><span>{item.name}</span></button>)}</nav></main>;
}

function App() {
  const [profile, setProfile] = useState<any>(null);
  const [listings, setListings] = useState<any[]>([]);
  const [view, setView] = useState('Home');
  const [error, setError] = useState('');
  const loadProfile = async () => { const result = await api('/api/profile'); setProfile(result); };
  useEffect(() => { loadProfile().catch(() => undefined); api('/api/listings').then(setListings).catch(reason => setError(reason.message)); }, []);
  if (!profile) return <Auth onAuthenticated={loadProfile} />;
  if (view === 'Chat') return <CommunityChat api={api} onNavigate={setView} />;
  return <><NavigationDashboard profile={profile} listings={listings} view={view} setView={setView} api={api} logout={async () => { await api('/api/auth/logout', { method: 'POST' }); setProfile(null); }} />{error && <p className="error global-error">{error}</p>}</>;
  return <main><header><span>Menu</span><strong>CL-Service</strong><span>Alerts</span></header>{view === 'Home' && <section><h1>Welcome, {profile.nickname}</h1><p className="muted">A secure marketplace for escrow-protected transactions.</p><div className="actions"><button onClick={() => setView('Catalog')}>Browse Catalog</button><button onClick={() => setView('Deals')}>View Deals</button></div><h2>Recent listings</h2>{listings.slice(0, 3).map(listing => <article key={listing.id}><b>{listing.title}</b><p>{listing.currency} {listing.price} · {listing.seller.nickname}</p></article>)}</section>}{view === 'Catalog' && <section><h1>Catalog</h1>{listings.length ? listings.map(listing => <article key={listing.id}><b>{listing.title}</b><p>{listing.description}</p></article>) : <p>No listings found.</p>}</section>}{view === 'Deals' && <section><h1>Deals</h1><p>No active deals.</p></section>}{view === 'Profile' && <section><h1>Profile</h1><p>{profile.nickname}</p><LoadingButton loading={false} onClick={async () => { await api('/api/auth/logout', { method: 'POST' }); setProfile(null); }}>Logout</LoadingButton></section>}<nav>{['Home', 'Catalog', 'Deals', 'Profile'].map(item => <button className={view === item ? 'active' : ''} onClick={() => setView(item)} key={item}>{item}</button>)}</nav>{error && <p className="error">{error}</p>}</main>;
}

createRoot(document.getElementById('root')!).render(<App />);
