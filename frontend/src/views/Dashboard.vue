<script setup>
// The Dashboard is a health view: what needs attention, how the fleet and
// each zone are doing, and the traffic curve. Everything here is read from
// the control plane's own store (one sample per reconcile cycle), so the page
// loads instantly and never waits on a slow server. Per-server detail and the
// top lists live on the Traffic page.
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import ZoneBadge from '../components/ZoneBadge.vue'
import SeriesChart from '../components/SeriesChart.vue'

const auth = useAuth()
const stats = ref(null)
const zones = ref([])
const servers = ref([])
const agents = ref([])
const lbs = ref([])
const overview = ref(null)
const attention = ref([])
const series = ref(null)
const range = ref('24h')
const chartZone = ref('')
const syncing = ref(false)
const msg = ref('')
const loading = ref(true)
let timer = null

const SERIES = [
  { key: 'qps', label: 'Queries/s', color: 'var(--chart-queries)' },
  { key: 'bps', label: 'Blocked/s', color: 'var(--chart-blocked)' },
]
const RANGES = [['1h', '1 hour'], ['6h', '6 hours'], ['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days']]
const RANGE_SECONDS = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000 }

async function loadBase() {
  const [s, z, sv] = await Promise.all([api.get('/stats'), api.get('/zones'), api.get('/servers')])
  stats.value = s.data
  zones.value = z.data
  servers.value = sv.data
  const [a, l, o, att] = await Promise.allSettled([
    api.get('/agents'), api.get('/load-balancers'), api.get('/metrics/overview'), api.get('/metrics/attention'),
  ])
  agents.value = a.status === 'fulfilled' ? a.value.data : []
  lbs.value = l.status === 'fulfilled' ? l.value.data : []
  overview.value = o.status === 'fulfilled' ? o.value.data : null
  attention.value = att.status === 'fulfilled' ? att.value.data : []
}

async function loadSeries() {
  const params = { range: range.value }
  if (chartZone.value) params.zone_id = Number(chartZone.value)
  try { series.value = (await api.get('/metrics/series', { params })).data } catch { series.value = null }
}

async function refresh() {
  try { await Promise.all([loadBase(), loadSeries()]) } finally { loading.value = false }
}

watch([range, chartZone], loadSeries)

async function syncNow() {
  syncing.value = true
  msg.value = ''
  try {
    await api.post('/sync/run')
    await refresh()
    msg.value = 'Reconciliation complete'
  } catch (e) {
    msg.value = e.response?.data?.detail || 'Sync failed'
  } finally {
    syncing.value = false
  }
}

onMounted(async () => {
  await refresh()
  timer = setInterval(refresh, 60000)
})
onBeforeUnmount(() => timer && clearInterval(timer))

// ---- derived ---------------------------------------------------------------
const agentName = (id) => agents.value.find((a) => a.id === id)?.name || null
const zoneTraffic = (zoneId) => overview.value?.zones?.find((z) => z.zone_id === zoneId) || null
function zoneCard(z) {
  const zoneLbs = lbs.value.filter((l) => l.zone_id === z.id)
  const owner = zoneLbs.find((l) => l.keepalived_state?.vip_owner) || null
  const src = owner || zoneLbs[0] || null
  const backends = src?.backends || []
  const t = zoneTraffic(z.id)
  const zoneServers = servers.value.filter((s) => s.zone_id === z.id && s.enabled !== false)
  return {
    traffic: t,
    owner: owner ? (agentName(owner.agent_id) || owner.name) : null,
    balancers: zoneLbs.length,
    mode: zoneLbs[0]?.mode || null,
    backendsUp: backends.filter((b) => b.live?.state === 'up' && !b.live?.drained).length,
    backendsTotal: backends.length,
    servers: zoneServers.length,
    serversOnline: zoneServers.filter((s) => s.status === 'online').length,
  }
}
const num = (n) => (n == null ? '—' : Number(n).toLocaleString())
const fixed = (n, d = 1) => (n == null ? '—' : Number(n).toFixed(d))
function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }
function ago(d) {
  if (!d) return '—'
  const s = Math.max(0, (Date.now() - new Date(d).getTime()) / 1000)
  return s < 90 ? `${Math.round(s)} s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`
}
const critical = computed(() => attention.value.filter((i) => i.severity === 'critical').length)
const warnings = computed(() => attention.value.filter((i) => i.severity === 'warning').length)
const tiles = computed(() => {
  const s = stats.value || {}
  const list = [
    { label: 'Servers online', value: s.servers_online ?? 0, of: s.servers ?? 0, link: '/servers' },
    { label: 'Servers in sync', value: s.servers_in_sync ?? 0, of: s.servers ?? 0, link: '/servers' },
  ]
  if (s.agents != null) list.push({ label: 'Hosts online', value: s.agents_online ?? 0, of: s.agents, link: '/hosts' })
  if (s.load_balancers != null) list.push({ label: 'Balancers in sync', value: s.load_balancers_in_sync ?? 0, of: s.load_balancers, link: '/load-balancers' })
  return list
})
</script>

<template>
  <div class="topbar">
    <h1>Dashboard</h1>
    <div class="flex" style="gap:10px;align-items:center">
      <span v-if="stats" class="muted" :title="fmt(stats.last_sync)">Last sync {{ ago(stats.last_sync) }}</span>
      <button v-if="auth.isEditor" class="btn btn-primary" :disabled="syncing" @click="syncNow">
        <span v-if="syncing" class="spinner"></span>
        <span>Sync now</span>
      </button>
    </div>
  </div>
  <div class="content" v-if="stats">
    <div v-if="msg" class="alert alert-success">{{ msg }}</div>

    <!-- Needs attention -->
    <div class="card attention" :class="critical ? 'has-critical' : warnings ? 'has-warning' : 'all-clear'" style="margin-bottom:24px">
      <div class="card-header">
        <h2>
          <span v-if="!attention.length">All clear</span>
          <span v-else>Needs attention</span>
        </h2>
        <span class="muted" v-if="attention.length">{{ critical }} critical · {{ warnings }} warning{{ warnings === 1 ? '' : 's' }}</span>
        <span class="muted" v-else>{{ stats.servers_online }} of {{ stats.servers }} servers reporting</span>
      </div>
      <div v-if="attention.length" class="attention-list">
        <router-link v-for="(i, idx) in attention" :key="idx" :to="i.link" class="attention-item">
          <span class="sev-dot" :class="i.severity"></span>
          <span class="attention-kind">{{ i.kind.replace('_', ' ') }}</span>
          <strong>{{ i.name }}</strong>
          <span class="attention-msg">{{ i.message }}</span>
        </router-link>
      </div>
      <div v-else class="hint" style="padding:0 16px 14px">Every server, host and balancer is online and in sync.</div>
    </div>

    <!-- Fleet -->
    <div class="stats-grid stats-grid-compact">
      <router-link v-for="t in tiles" :key="t.label" :to="t.link" class="stat stat-link">
        <div class="value" :class="t.of ? (t.value === t.of ? 'green' : 'red') : ''">{{ t.value }}<span class="muted" style="font-size:18px">/{{ t.of }}</span></div>
        <div class="label">{{ t.label }}</div>
      </router-link>
      <div class="stat">
        <div class="value">{{ overview?.fleet?.qps == null ? '—' : fixed(overview.fleet.qps) }}</div>
        <div class="label">Queries/s now</div>
      </div>
      <div class="stat">
        <div class="value">{{ overview?.fleet ? overview.fleet.blocked_pct + '%' : '—' }}</div>
        <div class="label">Blocked, last 24 h</div>
      </div>
    </div>

    <!-- Zones -->
    <template v-if="zones.length">
      <div class="toolbar"><h2 style="font-size:16px">Zones</h2><router-link class="muted" to="/zones">Zones →</router-link></div>
      <div class="stats-grid">
        <div v-for="z in zones" :key="z.id" class="tile">
          <div class="flex gap-between">
            <ZoneBadge :id="z.id" :label="z.name" />
            <span v-if="zoneCard(z).mode" class="badge" :class="'mode-' + zoneCard(z).mode">{{ zoneCard(z).mode }}</span>
          </div>
          <div v-if="z.vip" class="vip" style="margin-top:8px">{{ z.vip }}</div>
          <div v-if="z.vip" class="row">
            <span class="muted">VIP owner</span>
            <strong v-if="zoneCard(z).owner">{{ zoneCard(z).owner }}</strong>
            <span v-else-if="!zoneCard(z).balancers" style="color:var(--amber)">no balancer</span>
            <span v-else style="color:var(--red)">none</span>
          </div>
          <div class="row">
            <span class="muted">Queries/s</span>
            <strong>{{ zoneCard(z).traffic?.qps == null ? '—' : fixed(zoneCard(z).traffic.qps) }}</strong>
          </div>
          <div class="row">
            <span class="muted">Blocked, 24 h</span>
            <strong>{{ zoneCard(z).traffic ? zoneCard(z).traffic.blocked_pct + '%' : '—' }}</strong>
          </div>
          <div class="row">
            <span class="muted">Servers online</span>
            <strong :style="zoneCard(z).servers && zoneCard(z).serversOnline < zoneCard(z).servers ? 'color:var(--amber)' : ''">{{ zoneCard(z).serversOnline }} / {{ zoneCard(z).servers }}</strong>
          </div>
          <div v-if="zoneCard(z).balancers" class="row">
            <span class="muted">Backends up</span>
            <strong :style="zoneCard(z).backendsTotal && zoneCard(z).backendsUp < zoneCard(z).backendsTotal ? 'color:var(--amber)' : ''">{{ zoneCard(z).backendsUp }} / {{ zoneCard(z).backendsTotal }}</strong>
          </div>
          <div class="row" style="margin-top:10px">
            <router-link class="muted" :to="{ path: '/traffic', query: { zone: z.id } }">Traffic →</router-link>
            <router-link v-if="z.vip" class="muted" to="/load-balancers">Balancers →</router-link>
          </div>
        </div>
      </div>
    </template>

    <!-- Traffic -->
    <div class="card" style="margin-top:8px">
      <div class="card-header">
        <h2>Traffic</h2>
        <div class="filters">
          <select v-model="chartZone">
            <option value="">All zones</option>
            <option v-for="z in zones" :key="z.id" :value="String(z.id)">{{ z.name }}</option>
          </select>
          <select v-model="range">
            <option v-for="[v, l] in RANGES" :key="v" :value="v">{{ l }}</option>
          </select>
          <router-link class="muted" to="/traffic">Details →</router-link>
        </div>
      </div>
      <div style="padding:8px 16px 14px">
        <SeriesChart :points="series?.points || []" :series="SERIES" :range-seconds="RANGE_SECONDS[range]" :height="240" />
        <div class="hint" style="margin-top:8px">
          Fleet-wide, summed over {{ series?.entities ?? 0 }} server{{ series?.entities === 1 ? '' : 's' }}, one point per {{ series ? (series.step_s >= 3600 ? series.step_s / 3600 + ' h' : series.step_s / 60 + ' min') : '…' }}.
          <span v-if="overview?.as_of">Latest sample {{ ago(overview.as_of) }}.</span>
        </div>
      </div>
    </div>
  </div>
  <div v-else-if="!loading" class="content"><div class="empty">Could not load the dashboard.</div></div>
</template>
