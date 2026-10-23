<script setup>
// Traffic detail: the fleet curve over a chosen range, per-server totals and
// the merged top lists. Totals and top lists are AdGuard's own statistics
// window (24 h by default) as stored by the collector; the curve is built
// from stored samples.
import { onBeforeUnmount, onMounted, ref, watch, computed } from 'vue'
import { useRoute } from 'vue-router'
import api from '../api'
import SeriesChart from '../components/SeriesChart.vue'

const route = useRoute()
const zones = ref([])
const servers = ref([])
const metrics = ref(null)
const series = ref(null)
const loading = ref(false)
const filterZone = ref(route.query.zone ? String(route.query.zone) : '')
const filterServer = ref(route.query.server ? String(route.query.server) : '')
const range = ref('24h')
let timer = null

const SERIES = [
  { key: 'qps', label: 'Queries/s', color: 'var(--chart-queries)' },
  { key: 'bps', label: 'Blocked/s', color: 'var(--chart-blocked)' },
]
const RANGES = [['1h', '1 hour'], ['6h', '6 hours'], ['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days']]
const RANGE_SECONDS = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000 }

const serverOptions = computed(() =>
  filterZone.value ? servers.value.filter((s) => String(s.zone_id) === filterZone.value) : servers.value
)
function params() {
  const p = {}
  if (filterZone.value) p.zone_id = Number(filterZone.value)
  if (filterServer.value) p.server_id = Number(filterServer.value)
  return p
}
async function load() {
  loading.value = true
  try {
    const [m, s] = await Promise.all([
      api.get('/metrics', { params: params() }),
      api.get('/metrics/series', { params: { ...params(), range: range.value } }),
    ])
    metrics.value = m.data
    series.value = s.data
  } finally {
    loading.value = false
  }
}
watch(filterZone, () => { filterServer.value = '' })
watch([filterZone, filterServer, range], load)

onMounted(async () => {
  const [z, sv] = await Promise.all([api.get('/zones'), api.get('/servers')])
  zones.value = z.data
  servers.value = sv.data
  await load()
  timer = setInterval(load, 60000)
})
onBeforeUnmount(() => timer && clearInterval(timer))

const num = (n) => (n == null ? '—' : Number(n).toLocaleString())
function ago(d) {
  if (!d) return null
  const s = Math.max(0, (Date.now() - new Date(d).getTime()) / 1000)
  return s < 90 ? `${Math.round(s)} s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`
}
</script>

<template>
  <div class="topbar">
    <h1>Traffic</h1>
    <div class="filters">
      <select v-model="filterZone">
        <option value="">All zones</option>
        <option v-for="z in zones" :key="z.id" :value="String(z.id)">{{ z.name }}</option>
      </select>
      <select v-model="filterServer">
        <option value="">All servers</option>
        <option v-for="s in serverOptions" :key="s.id" :value="String(s.id)">{{ s.name }}</option>
      </select>
      <select v-model="range">
        <option v-for="[v, l] in RANGES" :key="v" :value="v">{{ l }}</option>
      </select>
    </div>
  </div>
  <div class="content">
    <div class="card" style="margin-bottom:24px">
      <div class="card-header">
        <h2>Queries over time</h2>
        <span class="muted" v-if="series">one point per {{ series.step_s >= 3600 ? series.step_s / 3600 + ' h' : series.step_s / 60 + ' min' }} · {{ series.entities }} server{{ series.entities === 1 ? '' : 's' }}</span>
      </div>
      <div style="padding:8px 16px 14px">
        <SeriesChart :points="series?.points || []" :series="SERIES" :range-seconds="RANGE_SECONDS[range]" :height="280" />
      </div>
    </div>

    <template v-if="metrics">
      <div class="toolbar">
        <h2 style="font-size:16px">Statistics window</h2>
        <span class="muted">{{ metrics.reporting }}/{{ metrics.selected }} reporting<span v-if="metrics.as_of"> · as of {{ ago(metrics.as_of) }}</span><span v-if="loading"> · refreshing…</span></span>
      </div>
      <div class="stats-grid">
        <div class="stat"><div class="value">{{ num(metrics.totals.num_dns_queries) }}</div><div class="label">DNS queries</div></div>
        <div class="stat"><div class="value">{{ num(metrics.totals.num_blocked) }}</div><div class="label">Blocked</div></div>
        <div class="stat"><div class="value">{{ metrics.totals.blocked_pct }}%</div><div class="label">Blocked rate</div></div>
        <div class="stat"><div class="value">{{ metrics.totals.avg_processing_ms }}<span class="muted" style="font-size:16px"> ms</span></div><div class="label">Avg processing</div></div>
      </div>

      <div class="card" style="margin-bottom:24px">
        <div class="card-header"><h2>Per-server breakdown</h2><router-link class="muted" to="/servers">Servers →</router-link></div>
        <table>
          <thead><tr><th>Server</th><th>Queries</th><th>Blocked</th><th>Blocked %</th><th>Avg ms</th><th>Share</th></tr></thead>
          <tbody>
            <tr v-for="s in metrics.servers" :key="s.server_id">
              <td><strong>{{ s.name }}</strong></td>
              <template v-if="s.online">
                <td>{{ num(s.num_dns_queries) }}</td>
                <td class="muted">{{ num(s.num_blocked) }}</td>
                <td>{{ s.blocked_pct }}%</td>
                <td class="muted">{{ s.avg_processing_ms }}</td>
                <td>
                  <div class="share-cell">
                    <div class="share-bar up"><span :style="{ width: (metrics.totals.num_dns_queries ? (s.num_dns_queries / metrics.totals.num_dns_queries) * 100 : 0).toFixed(1) + '%' }"></span></div>
                    <span class="pct">{{ metrics.totals.num_dns_queries ? ((s.num_dns_queries / metrics.totals.num_dns_queries) * 100).toFixed(0) : 0 }}%</span>
                  </div>
                </td>
              </template>
              <template v-else>
                <td colspan="5" class="muted">offline — {{ s.error }}</td>
              </template>
            </tr>
            <tr v-if="!metrics.servers.length"><td colspan="6" class="empty">No servers match this filter.</td></tr>
          </tbody>
        </table>
        <div class="hint" style="padding:10px 16px">
          Totals, shares and the lists below cover AdGuard's own statistics window (24 hours unless changed on the server), as read by the last collection cycle.
        </div>
      </div>

      <div class="stats-grid" style="align-items:start">
        <div class="card">
          <div class="card-header"><h2>Top queried</h2></div>
          <table><tbody>
            <tr v-for="d in metrics.top_queried" :key="d.name">
              <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis">{{ d.name }}</td>
              <td style="text-align:right">{{ num(d.count) }}</td>
            </tr>
            <tr v-if="!metrics.top_queried.length"><td class="empty">No data</td></tr>
          </tbody></table>
        </div>
        <div class="card">
          <div class="card-header"><h2>Top blocked</h2></div>
          <table><tbody>
            <tr v-for="d in metrics.top_blocked" :key="d.name">
              <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis">{{ d.name }}</td>
              <td style="text-align:right">{{ num(d.count) }}</td>
            </tr>
            <tr v-if="!metrics.top_blocked.length"><td class="empty">No data</td></tr>
          </tbody></table>
        </div>
        <div class="card">
          <div class="card-header"><h2>Top clients</h2></div>
          <table><tbody>
            <tr v-for="d in metrics.top_clients" :key="d.name">
              <td class="mono">{{ d.name }}</td>
              <td style="text-align:right">{{ num(d.count) }}</td>
            </tr>
            <tr v-if="!metrics.top_clients.length"><td class="empty">No data</td></tr>
          </tbody></table>
        </div>
      </div>
    </template>
  </div>
</template>
