import { ref } from 'vue'

const KEY = 'theme'
export const theme = ref('light')

function apply(t) {
  document.documentElement.setAttribute('data-theme', t)
  theme.value = t
}

export function initTheme() {
  const saved = localStorage.getItem(KEY)
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
  apply(saved || (prefersDark ? 'dark' : 'light'))
}

export function toggleTheme() {
  const next = theme.value === 'dark' ? 'light' : 'dark'
  apply(next)
  localStorage.setItem(KEY, next)
}
