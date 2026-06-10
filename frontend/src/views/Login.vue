<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../stores/auth'
import { theme, toggleTheme } from '../theme'

const auth = useAuth()
const router = useRouter()
const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

onMounted(async () => {
  await auth.loadConfig()
  // Handle the token handed back by the OIDC callback via URL fragment.
  const hash = new URLSearchParams(location.hash.slice(1))
  const token = hash.get('token')
  if (token) {
    auth.setToken(token)
    history.replaceState(null, '', location.pathname)
    try {
      await auth.fetchMe()
      router.push('/')
    } catch {
      error.value = 'OIDC sign-in failed'
    }
  }
})

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await auth.login(username.value, password.value)
    router.push('/')
  } catch (e) {
    error.value = e.response?.data?.detail || 'Login failed'
  } finally {
    loading.value = false
  }
}

function oidcLogin() {
  location.href = '/api/auth/oidc/login'
}
</script>

<template>
  <div class="login-wrap">
    <button class="btn btn-sm btn-icon" style="position:fixed;top:20px;right:20px"
            :title="theme === 'dark' ? 'Light mode' : 'Dark mode'" @click="toggleTheme">
      {{ theme === 'dark' ? '☀' : '☾' }}
    </button>
    <div class="login-card">
      <div class="login-logo"><img src="/icon.svg" class="login-icon" alt="AdGuard Admin" /></div>
      <h1>AdGuard Admin</h1>
      <p class="login-sub">Sign in to manage your DNS fleet</p>

      <div v-if="error" class="alert alert-error">{{ error }}</div>

      <form @submit.prevent="submit">
        <div class="form-row">
          <label>Username</label>
          <input v-model="username" autocomplete="username" required />
        </div>
        <div class="form-row">
          <label>Password</label>
          <input v-model="password" type="password" autocomplete="current-password" required />
        </div>
        <button class="btn btn-primary" style="width:100%" :disabled="loading">
          <span v-if="loading" class="spinner"></span>
          <span>Sign in</span>
        </button>
      </form>

      <template v-if="auth.oidcEnabled">
        <div class="divider">or</div>
        <button class="btn" style="width:100%" @click="oidcLogin">{{ auth.oidcLabel }}</button>
      </template>
    </div>
  </div>
</template>
