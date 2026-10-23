<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import ZoneBadge from '../components/ZoneBadge.vue'

const auth = useAuth()
const stats = ref(null)
const servers = ref([])
const zones = ref([])
const metrics = ref(null)
const agents = ref([])
const lbs = ref([])
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
  // Hosts and balancers are optional context; an older backend simply has none.
  const [a, l] = await Promise.allSettled([api.get('/agents'), api.get('/load-balancers')])
  agents.value = a.status === 'fulfilled' ? a.value.data : []
  lbs.value = l.status === 'fulfilled' ? l.value.data : []
}

// One tile per zone that has a VIP: who holds it, how busy it is, how many backends are up.
const vipZones = computed(() => zones.value.filter((z) => z.vip))
function vipTile(z) {
  const zoneLbs = lbs.value.filter((l) => l.zone_id === z.id)
  const owner = zoneLbs.find((l) => l.keepalived_state?.vip_owner) || null
  const src = owner || zoneLbs[0] || null
  const backends = src?.backends || []
  const live = backends.filter((b) => b.live)
  return {
    owner: owner ? (agents.value.find((a) => a.id === owner.agent_id)?.name || owner.name) : null,
    balancers: zoneLbs.length,
    qps: live.length ? live.reduce((n, b) => n + Number(b.live.qps || 0), 0) : null,
    up: backends.filter((b) => b.live?.state === 'up' && !b.live?.drained).length,
    total: backends.length,
    status: src?.status || 'unknown',
  }
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
      <div class="stat" v-if="stats.agents != null">
        <div class="value" :class="stats.agents && stats.agents_online === stats.agents ? 'green' : (stats.agents ? 'red' : '')">{{ stats.agents_online ?? 0 }}<span class="muted" style="font-size:18px">/{{ stats.agents }}</span></div>
        <div class="label">Hosts online</div>
      </div>
      <div class="stat" v-if="stats.load_balancers != null">
        <div class="value" :class="stats.load_balancers && stats.load_balancers_in_sync === stats.load_balancers ? 'green' : (stats.load_balancers ? 'red' : '')">{{ stats.load_balancers_in_sync ?? 0 }}<span class="muted" style="font-size:18px">/{{ stats.load_balancers }}</span></div>
        <div class="label">Balancers in sync</div>
      </div>
    </div>

    <!-- Zone virtual IPs -->
    <template v-if="vipZones.length">
      <div class="toolbar"><h2 style="font-size:16px">Virtual IPs</h2><router-link class="muted" to="/load-balancers">Load balancers →</router-link></div>
      <div class="stats-grid">
        <div v-for="z in vipZones" :key="z.id" class="vip-tile">
          <div class="flex gap-between">
            <ZoneBadge :id="z.id" :label="z.name" />
            <span class="badge" :class="vipTile(z).status"><span class="dot"></span>{{ vipTile(z).status }}</span>
          </div>
          <div class="vip" style="margin-top:8px">{{ z.vip }}</div>
          <div class="row">
            <span class="muted">Owner</span>
            <strong v-if="vipTile(z).owner">{{ vipTile(z).owner }}</strong>
            <span v-else-if="!vipTile(z).balancers" style="color:var(--amber)">no balancer in zone</span>
            <span v-else class="muted">unknown</span>
          </div>
          <div class="row">
            <span class="muted">Queries/s</span>
            <strong>{{ vipTile(z).qps == null ? '—' : vipTile(z).qps.toFixed(1) }}</strong>
          </div>
          <div class="row">
            <span class="muted">Backends up</span>
            <strong :style="vipTile(z).total && vipTile(z).up < vipTile(z).total ? 'color:var(--amber)' : ''">{{ vipTile(z).up }} / {{ vipTile(z).total }}</strong>
          </div>
        </div>
      </div>
    </template>

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
            <td><ZoneBadge :id="s.zone_id" :label="zoneName(s.zone_id)" /></td>
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
