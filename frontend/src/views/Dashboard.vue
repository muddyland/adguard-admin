<script setup>
import { ref, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const stats = ref(null)
const servers = ref([])
const syncing = ref(false)
const msg = ref('')

async function load() {
  const [s, sv] = await Promise.all([api.get('/stats'), api.get('/servers')])
  stats.value = s.data
  servers.value = sv.data
}

async function syncNow() {
  syncing.value = true
  msg.value = ''
  try {
    await api.post('/sync/run')
    await load()
    msg.value = 'Reconciliation complete'
  } catch (e) {
    msg.value = e.response?.data?.detail || 'Sync failed'
  } finally {
    syncing.value = false
  }
}

function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Dashboard</h1>
    <button v-if="auth.isEditor" class="btn btn-primary" :disabled="syncing" @click="syncNow">
      <span v-if="syncing" class="spinner"></span>
      <span>Sync now</span>
    </button>
  </div>
  <div class="content" v-if="stats">
    <div v-if="msg" class="alert alert-success">{{ msg }}</div>

    <div class="stats-grid">
      <div class="stat"><div class="value">{{ stats.zones }}</div><div class="label">Zones</div></div>
      <div class="stat">
        <div class="value green">{{ stats.servers_online }}<span class="muted" style="font-size:18px">/{{ stats.servers }}</span></div>
        <div class="label">Servers online</div>
      </div>
      <div class="stat">
        <div class="value" :class="stats.servers_in_sync === stats.servers ? 'green' : 'red'">{{ stats.servers_in_sync }}</div>
        <div class="label">Servers in sync</div>
      </div>
      <div class="stat"><div class="value">{{ stats.records }}</div><div class="label">DNS records</div></div>
      <div class="stat"><div class="value">{{ stats.records_global }}</div><div class="label">Global records</div></div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>Server status</h2>
        <span class="muted">Last sync: {{ fmt(stats.last_sync) }}</span>
      </div>
      <table>
        <thead>
          <tr><th>Server</th><th>Status</th><th>Sync</th><th>Version</th><th>Last seen</th><th>Last error</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in servers" :key="s.id">
            <td><strong>{{ s.name }}</strong><div class="muted mono">{{ s.url }}</div></td>
            <td><span class="badge" :class="s.status"><span class="dot"></span>{{ s.status }}</span></td>
            <td>
              <span v-if="s.in_sync" class="badge synced">In sync</span>
              <span v-else class="badge drift">Drift</span>
            </td>
            <td class="muted">{{ s.version || '—' }}</td>
            <td class="muted">{{ fmt(s.last_seen) }}</td>
            <td class="muted mono" style="max-width:220px">{{ s.last_error || '—' }}</td>
          </tr>
          <tr v-if="!servers.length"><td colspan="6" class="empty">No servers yet. Add one under Servers.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
