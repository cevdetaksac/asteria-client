import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/bruno-ace/400.css'
import App from './App'
import { isNativeHost } from './bridge'
import { installMockBridge } from './mockBridge'
import './style.css'

function boot() {
  // Native host injects window.pywebview.api asynchronously; the bridge waits
  // for it. Only a plain browser (Vite preview) gets the mock.
  if (!isNativeHost()) {
    installMockBridge()
  }
  createRoot(document.getElementById('app')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

boot()
