<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const stats = ref(null)
const servers = ref([])
const zones = ref([])
const metrics = ref(null)
const metricsLoading = ref(false)
const syncing = ref(false)
const msg = ref('')

// Filters for the traffic metrics section
const filterZone = ref('')
const filterServer = ref('')

// Server dropdown options narrow to the selected zone.
const serverOptions = computed(() =>
  filterZone.value ? servers.value.filter((s) => String(s.zone_id) === filterZone.value) : servers.value
)

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || 'Unzoned'
const num = (n) => (n ?? 0).toLocaleString()

async function loadBase() {
  const [s, sv, z] = await Promise.all([api.get('/stats'), api.get('/servers'), api.get('/zones')])
  stats.value = s.data
  servers.value = sv.data
  zones.value = z.data
}

async function loadMetrics() {
  metricsLoading.value = true
  try {
    const params = {}
    if (filterZone.value) params.zone_id = Number(filterZone.value)
    if (filterServer.value) params.server_id = Number(filterServer.value)
    metrics.value = (await api.get('/metrics', { params })).data
  } finally {
    metricsLoading.value = false
  }
}

// Changing the zone clears a now-irrelevant server selection.
watch(filterZone, () => { filterServer.value = '' })
watch([filterZone, filterServer], loadMetrics)

async function syncNow() {
  syncing.value = true
  msg.value = ''
  try {
    await api.post('/sync/run')
    await Promise.all([loadBase(), loadMetrics()])
    msg.value = 'Reconciliation complete'
  } catch (e) {
    msg.value = e.response?.data?.detail || 'Sync failed'
  } finally {
    syncing.value = false
  }
}

function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

onMounted(async () => { await loadBase(); await loadMetrics() })
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

    <!-- Fleet overview -->
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

    <!-- Traffic metrics -->
    <div class="toolbar">
      <h2 style="font-size:16px">Traffic metrics</h2>
      <div class="filters">
        <select v-model="filterZone">
          <option value="">All zones</option>
          <option v-for="z in zones" :key="z.id" :value="String(z.id)">{{ z.name }}</option>
        </select>
        <select v-model="filterServer">
          <option value="">All servers</option>
          <option v-for="s in serverOptions" :key="s.id" :value="String(s.id)">{{ s.name }}</option>
        </select>
        <span class="muted" v-if="metrics">{{ metrics.reporting }}/{{ metrics.selected }} reporting</span>
      </div>
    </div>

    <div v-if="metrics">
      <div class="stats-grid">
        <div class="stat"><div class="value">{{ num(metrics.totals.num_dns_queries) }}</div><div class="label">DNS queries</div></div>
        <div class="stat"><div class="value red">{{ num(metrics.totals.num_blocked) }}</div><div class="label">Blocked</div></div>
        <div class="stat"><div class="value">{{ metrics.totals.blocked_pct }}%</div><div class="label">Blocked rate</div></div>
        <div class="stat"><div class="value">{{ metrics.totals.avg_processing_ms }}<span class="muted" style="font-size:16px"> ms</span></div><div class="label">Avg processing</div></div>
      </div>

      <!-- Per-server breakdown -->
      <div class="card" style="margin-bottom:24px">
        <div class="card-header">
          <h2>Per-server breakdown</h2>
          <span v-if="metricsLoading" class="muted">refreshing…</span>
        </div>
        <table>
          <thead><tr><th>Server</th><th>Queries</th><th>Blocked</th><th>Blocked %</th><th>Avg ms</th></tr></thead>
          <tbody>
            <tr v-for="s in metrics.servers" :key="s.server_id">
              <td><strong>{{ s.name }}</strong></td>
              <template v-if="s.online">
                <td>{{ num(s.num_dns_queries) }}</td>
                <td class="muted">{{ num(s.num_blocked) }}</td>
                <td>{{ s.blocked_pct }}%</td>
                <td class="muted">{{ s.avg_processing_ms }}</td>
              </template>
              <template v-else>
                <td colspan="4" class="muted">offline — {{ s.error }}</td>
              </template>
            </tr>
            <tr v-if="!metrics.servers.length"><td colspan="5" class="empty">No servers match this filter.</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Top lists -->
      <div class="stats-grid" style="align-items:start">
        <div class="card">
          <div class="card-header"><h2>Top queried</h2></div>
          <table>
            <tbody>
              <tr v-for="d in metrics.top_queried" :key="d.name">
                <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ d.name }}</td>
                <td style="text-align:right">{{ num(d.count) }}</td>
              </tr>
              <tr v-if="!metrics.top_queried.length"><td class="empty">No data</td></tr>
            </tbody>
          </table>
        </div>
        <div class="card">
          <div class="card-header"><h2>Top blocked</h2></div>
          <table>
            <tbody>
              <tr v-for="d in metrics.top_blocked" :key="d.name">
                <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ d.name }}</td>
                <td style="text-align:right">{{ num(d.count) }}</td>
              </tr>
              <tr v-if="!metrics.top_blocked.length"><td class="empty">No data</td></tr>
            </tbody>
          </table>
        </div>
        <div class="card">
          <div class="card-header"><h2>Top clients</h2></div>
          <table>
            <tbody>
              <tr v-for="d in metrics.top_clients" :key="d.name">
                <td class="mono">{{ d.name }}</td>
                <td style="text-align:right">{{ num(d.count) }}</td>
              </tr>
              <tr v-if="!metrics.top_clients.length"><td class="empty">No data</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Server sync status -->
    <div class="card" style="margin-top:24px">
      <div class="card-header">
        <h2>Server status</h2>
        <span class="muted">Last sync: {{ fmt(stats.last_sync) }}</span>
      </div>
      <table>
        <thead>
          <tr><th>Server</th><th>Zone</th><th>Status</th><th>Sync</th><th>Version</th><th>Last seen</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in servers" :key="s.id">
            <td><strong>{{ s.name }}</strong><div class="muted mono">{{ s.url }}</div></td>
            <td>{{ zoneName(s.zone_id) }}</td>
            <td><span class="badge" :class="s.status"><span class="dot"></span>{{ s.status }}</span></td>
            <td>
              <span v-if="s.in_sync" class="badge synced">In sync</span>
              <span v-else class="badge drift">Drift</span>
            </td>
            <td class="muted">{{ s.version || '—' }}</td>
            <td class="muted">{{ fmt(s.last_seen) }}</td>
          </tr>
          <tr v-if="!servers.length"><td colspan="6" class="empty">No servers yet. Add one under Servers.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
