import { defineStore } from 'pinia'
import api from '../api'

export const useAuth = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('token') || null,
    user: null,
    oidcEnabled: false,
    oidcLabel: 'Sign in with OIDC',
  }),
  getters: {
    isAuthenticated: (s) => !!s.token,
    isAdmin: (s) => s.user?.role === 'admin',
    isEditor: (s) => s.user?.role === 'admin' || s.user?.role === 'editor',
  },
  actions: {
    async loadConfig() {
      try {
        const { data } = await api.get('/auth/config')
        this.oidcEnabled = data.oidc_enabled
        this.oidcLabel = data.oidc_label
      } catch { /* ignore */ }
    },
    setToken(token) {
      this.token = token
      localStorage.setItem('token', token)
    },
    async login(username, password) {
      const body = new URLSearchParams({ username, password })
      const { data } = await api.post('/auth/token', body)
      this.setToken(data.access_token)
      await this.fetchMe()
    },
    async fetchMe() {
      const { data } = await api.get('/auth/me')
      this.user = data
      return data
    },
    logout() {
      this.token = null
      this.user = null
      localStorage.removeItem('token')
    },
  },
})
