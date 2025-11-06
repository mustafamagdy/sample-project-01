import { useEffect, useMemo, useState } from 'react';
import './App.css';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:4000';

function App() {
  const [authMode, setAuthMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(() => localStorage.getItem('susa_token'));
  const [links, setLinks] = useState([]);
  const [form, setForm] = useState({ targetUrl: '', slug: '', expiresAt: '' });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [stats, setStats] = useState(null);

  const authHeader = useMemo(() => ({
    Authorization: token ? `Bearer ${token}` : ''
  }), [token]);

  useEffect(() => {
    if (!token) {
      setLinks([]);
      return;
    }

    let cancelled = false;

    const fetchLinks = async () => {
      try {
        const res = await fetch(`${API_BASE}/links`, { headers: authHeader });
        if (!res.ok) {
          throw new Error('Failed to load links');
        }
        const data = await res.json();
        if (!cancelled) {
          const normalised = (data.links || []).map((link) => ({ ...link, slug: link.slug || link.alias }));
          setLinks(normalised);
        }
      } catch (err) {
        console.error(err);
        if (!cancelled) {
          setMessage({ type: 'error', text: 'Unable to fetch links. Please log in again.' });
          handleLogout();
        }
      }
    };

    fetchLinks();

    return () => {
      cancelled = true;
    };
  }, [token, authHeader]);

  const handleAuth = async (event) => {
    event.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const response = await fetch(`${API_BASE}/auth/${authMode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error || 'Authentication failed');
      }
      localStorage.setItem('susa_token', body.token);
      setToken(body.token);
      setEmail('');
      setPassword('');
      setMessage({ type: 'success', text: authMode === 'signup' ? 'Account created' : 'Logged in' });
    } catch (err) {
      setMessage({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateLink = async (event) => {
    event.preventDefault();
    if (!form.targetUrl.trim()) {
      setMessage({ type: 'error', text: 'Target URL is required' });
      return;
    }

    setLoading(true);
    setMessage(null);

    try {
      const response = await fetch(`${API_BASE}/links`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeader
        },
        body: JSON.stringify({
          targetUrl: form.targetUrl.trim(),
          slug: form.slug.trim() || undefined,
          expiresAt: form.expiresAt || undefined
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error || 'Could not create link');
      }
      const normalised = { ...body, slug: body.slug || body.alias };
      setLinks((prev) => [normalised, ...prev]);
      setForm({ targetUrl: '', slug: '', expiresAt: '' });
      setMessage({ type: 'success', text: 'Link created' });
    } catch (err) {
      setMessage({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this link?')) {
      return;
    }
    setMessage(null);
    try {
      const res = await fetch(`${API_BASE}/links/${id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      if (res.status === 204) {
        setLinks((prev) => prev.filter((link) => link.id !== id));
        if (stats?.link?.id === id) {
          setStats(null);
        }
        setMessage({ type: 'success', text: 'Link deleted' });
      } else {
        const body = await res.json();
        throw new Error(body.error || 'Could not delete link');
      }
    } catch (err) {
      setMessage({ type: 'error', text: err.message });
    }
  };

  const handleCopy = async (shortUrl) => {
    try {
      await navigator.clipboard.writeText(shortUrl);
      setMessage({ type: 'success', text: 'Short URL copied' });
    } catch (err) {
      setMessage({ type: 'error', text: 'Could not copy URL' });
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('susa_token');
    setToken(null);
    setStats(null);
  };

  const fetchStats = async (id) => {
    setMessage(null);
    try {
      const res = await fetch(`${API_BASE}/links/${id}/stats`, { headers: authHeader });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || 'Could not load stats');
      }
      setStats({
        ...body,
        link: {
          ...body.link,
          slug: body.link?.slug || body.link?.alias
        }
      });
    } catch (err) {
      setMessage({ type: 'error', text: err.message });
    }
  };

  if (!token) {
    return (
      <main className="auth">
        <h1>SUSA</h1>
        <p className="tagline">Secure URL Shortener with Analytics</p>
        <form onSubmit={handleAuth} className="card">
          <div className="toggle">
            <button type="button" className={authMode === 'login' ? 'active' : ''} onClick={() => setAuthMode('login')}>
              Login
            </button>
            <button type="button" className={authMode === 'signup' ? 'active' : ''} onClick={() => setAuthMode('signup')}>
              Sign Up
            </button>
          </div>
          <label>
            Email
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label>
            Password
            <input type="password" required minLength={6} value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <button type="submit" disabled={loading}>
            {loading ? 'Please wait…' : authMode === 'login' ? 'Log In' : 'Create Account'}
          </button>
          {message && <p className={`message ${message.type}`}>{message.text}</p>}
        </form>
        <p className="hint">Passwords need at least 6 characters. We’ll keep it simple.</p>
      </main>
    );
  }

  return (
    <main className="app">
      <header>
        <div>
          <h1>SUSA</h1>
          <p className="tagline">Short links, simple analytics.</p>
        </div>
        <button onClick={handleLogout}>Log out</button>
      </header>

      <section className="card">
        <h2>Create Short Link</h2>
        <form className="grid" onSubmit={handleCreateLink}>
          <label>
            Target URL
            <input type="url" required value={form.targetUrl} onChange={(e) => setForm((f) => ({ ...f, targetUrl: e.target.value }))} />
          </label>
          <label>
            Slug (optional)
            <input value={form.slug} onChange={(e) => setForm((f) => ({ ...f, slug: e.target.value }))} placeholder="custom-slug" />
          </label>
          <label>
            Expires At
            <input type="datetime-local" value={form.expiresAt} onChange={(e) => setForm((f) => ({ ...f, expiresAt: e.target.value }))} />
          </label>
          <button type="submit" disabled={loading} className="primary">
            {loading ? 'Saving…' : 'Shorten'}
          </button>
        </form>
      </section>

      {message && <p className={`message ${message.type}`}>{message.text}</p>}

      <section className="card">
        <h2>Your Links</h2>
        {links.length === 0 ? (
          <p>No links yet. Shorten something to get started.</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Slug</th>
                  <th>Target</th>
                  <th>Total Clicks</th>
                  <th>Last Click</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {links.map((link) => (
                  <tr key={link.id}>
                    <td>{link.slug || link.alias}</td>
                    <td>
                      <a href={link.targetUrl} target="_blank" rel="noreferrer">
                        {link.targetUrl}
                      </a>
                    </td>
                    <td>{link.totalClicks}</td>
                    <td>{link.lastClick ? new Date(link.lastClick).toLocaleString() : '—'}</td>
                    <td>
                      <div className="actions">
                        <button type="button" onClick={() => handleCopy(link.shortUrl)}>
                          Copy
                        </button>
                        <button type="button" onClick={() => fetchStats(link.id)}>
                          Stats
                        </button>
                        <button type="button" className="danger" onClick={() => handleDelete(link.id)}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {stats && (
        <section className="card">
          <div className="stats-header">
            <h2>Link Stats</h2>
            <button type="button" onClick={() => setStats(null)}>
              Close
            </button>
          </div>
          <p>
            <strong>Slug:</strong> {stats.link.slug || stats.link.alias}
          </p>
          <p>
            <strong>Total clicks:</strong> {stats.stats.totalClicks}
          </p>
          <p>
            <strong>Last click:</strong> {stats.stats.lastClick ? new Date(stats.stats.lastClick).toLocaleString() : '—'}
          </p>
          <h3>Top referrers</h3>
          {stats.stats.topReferrers.length === 0 ? (
            <p>No referrers recorded yet.</p>
          ) : (
            <ul>
              {stats.stats.topReferrers.map((row) => (
                <li key={row.referrer}>
                  {row.referrer} — {row.total}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </main>
  );
}

export default App;
