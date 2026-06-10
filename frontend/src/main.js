import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { initTheme } from './theme'
import './style.css'

initTheme()
createApp(App).use(createPinia()).use(router).mount('#app')

// Register the PWA service worker (enables install + offline app shell).
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {})
  })
}
