<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuth } from './stores/auth'
import { theme, toggleTheme } from './theme'

const route = useRoute()
const router = useRouter()
const auth = useAuth()

const showShell = computed(() => route.name !== 'login' && auth.isAuthenticated)

const nav = [
  { to: '/', label: 'Dashboard', icon: '▤' },
  { to: '/zones', label: 'Zones', icon: '◈' },
  { to: '/servers', label: 'Servers', icon: '⛁' },
  { to: '/records', label: 'DNS Records', icon: '⚲' },
  { to: '/dns-settings', label: 'DNS Settings', icon: '⚙' },
  { to: '/query-log', label: 'Query Log', icon: '☰' },
]
const editorNav = [
  { to: '/provision', label: 'Provisioning', icon: '✦' },
]

function logout() {
  auth.logout()
  router.push('/login')
}
</script>

<template>
  <div v-if="showShell" class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo">A</div>
        <span>AdGuard Admin</span>
      </div>
      <nav class="nav">
        <div class="section-label">Manage</div>
        <router-link v-for="item in nav" :key="item.to" :to="item.to">
          <span class="icon">{{ item.icon }}</span>{{ item.label }}
        </router-link>
        <template v-if="auth.isEditor">
          <router-link v-for="item in editorNav" :key="item.to" :to="item.to">
            <span class="icon">{{ item.icon }}</span>{{ item.label }}
          </router-link>
        </template>
        <template v-if="auth.isAdmin">
          <div class="section-label">Administration</div>
          <router-link to="/users"><span class="icon">⚇</span>Users</router-link>
        </template>
      </nav>
      <div class="sidebar-footer">
        <div class="flex gap-between">
          <div>
            <div class="user">{{ auth.user?.username }}</div>
            <div class="role">{{ auth.user?.role }}</div>
          </div>
          <div class="flex" style="gap:6px">
            <button class="btn btn-sm btn-icon" :title="theme === 'dark' ? 'Light mode' : 'Dark mode'" @click="toggleTheme">
              {{ theme === 'dark' ? '☀' : '☾' }}
            </button>
            <button class="btn btn-sm" @click="logout">Sign out</button>
          </div>
        </div>
      </div>
    </aside>
    <div class="main">
      <router-view />
    </div>
  </div>
  <router-view v-else />
</template>
