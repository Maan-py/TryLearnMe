import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter, Route, Routes, useParams } from 'react-router-dom'
import { getModule } from './content/modules'
import '@fontsource/source-sans-3/400.css'
import '@fontsource/source-sans-3/600.css'
import '@fontsource/ubuntu/500.css'
import '@fontsource/ubuntu/700.css'
import '@fontsource/ubuntu-mono/400.css'
import '@fontsource/ubuntu-mono/700.css'
import './styles.css'
import { Layout } from './components/Layout'
import { Home } from './pages/Home'
import { ModulePage } from './pages/ModulePage'
import { CheatSheet } from './pages/CheatSheet'

/** Halaman modul dipilih dari alamat. `key` memastikan keadaan tidak terbawa antar-modul. */
function ModuleRoute() {
  const mod = getModule(useParams().moduleId)
  return mod ? <ModulePage key={mod.id} mod={mod} /> : <Home />
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <HashRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Home />} />
          <Route path="/zeek/cheatsheet" element={<CheatSheet />} />
          <Route path="/:moduleId" element={<ModuleRoute />} />
          <Route path="*" element={<Home />} />
        </Route>
      </Routes>
    </HashRouter>
  </React.StrictMode>,
)
