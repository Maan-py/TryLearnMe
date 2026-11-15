import { NavLink, Outlet } from 'react-router-dom'
import { useTheme } from '../lib/theme'
import { MODULES } from '../content/modules'

export function Layout() {
  const [theme, toggle] = useTheme()
  return (
    <>
      <header className="site-header">
        <NavLink to="/" className="brand" aria-label="TryLearnMe, halaman depan">
          <span className="brand-mark" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          TryLearnMe
        </NavLink>
        <nav aria-label="Navigasi utama">
          {MODULES.map((m) => (
            <NavLink key={m.id} to={`/${m.id}`} end>
              {m.navTitle}
            </NavLink>
          ))}
          <NavLink to="/zeek/cheatsheet" className="nav-extra">
            Cheat sheet
          </NavLink>
          <button type="button" className="ghost-btn" onClick={toggle}>
            {theme === 'dark' ? 'Mode terang' : 'Mode gelap'}
          </button>
        </nav>
      </header>
      <Outlet />
    </>
  )
}
