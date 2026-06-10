<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import api from '../api'

const entries = ref([])
const zones = ref([])
const servers = ref([])
const loading = ref(false)
const meta = ref({ servers_queried: 0, total_fetched: 0 })

const filterZone = ref('')
const filterServer = ref('')
const search = ref('')
const status = ref('all')
const limit = ref(100)

const serverOptions = computed(() =>
  filterZone.value ? servers.value.filter((s) => String(s.zone_id) === filterZone.value) : servers.value
)

const STATUSES = [
  ['all', 'All'], ['blocked', 'Blocked'], ['filtered', 'Filtered'],
  ['processed', 'Allowed'], ['rewritten', 'Rewritten'],
  ['whitelisted', 'Allowlisted'], ['safe_search', 'Safe search'],
]

async function loadFilters() {
  const [z, s] = await Promise.all([api.get('/zones'), api.get('/servers')])
  zones.value = z.data
  servers.value = s.data
}

async function load() {
  loading.value = true
  try {
    const params = { response_status: status.value, limit: limit.value }
    if (filterZone.value) params.zone_id = Number(filterZone.value)
    if (filterServer.value) params.server_id = Number(filterServer.value)
    if (search.value.trim()) params.search = search.value.trim()
    const { data } = await api.get('/querylog', { params })
    entries.value = data.entries
    meta.value = { servers_queried: data.servers_queried, total_fetched: data.total_fetched }
  } finally {
    loading.value = false
  }
}

watch(filterZone, () => { filterServer.value = '' })
watch([filterZone, filterServer, status, limit], load)

// Debounce search typing.
let t
watch(search, () => { clearTimeout(t); t = setTimeout(load, 400) })

function fmt(d) {
  if (!d) return '—'
  const dt = new Date(d)
  return dt.toLocaleTimeString() + ' ' + dt.toLocaleDateString()
}

onMounted(async () => { await loadFilters(); await load() })
</script>

<template>
  <div class="topbar">
    <h1>Query Log</h1>
    <button class="btn btn-primary" :disabled="loading" @click="load">
      <span v-if="loading" class="spinner"></span><span>Refresh</span>
    </button>
  </div>
  <div class="content">
    <div class="toolbar">
      <div class="filters">
        <input v-model="search" placeholder="Search domain or client…" style="min-width:240px" />
        <select v-model="filterZone">
          <option value="">All zones</option>
          <option v-for="z in zones" :key="z.id" :value="String(z.id)">{{ z.name }}</option>
        </select>
        <select v-model="filterServer">
          <option value="">All servers</option>
          <option v-for="s in serverOptions" :key="s.id" :value="String(s.id)">{{ s.name }}</option>
        </select>
        <select v-model="status">
          <option v-for="[v, label] in STATUSES" :key="v" :value="v">{{ label }}</option>
        </select>
        <select v-model.number="limit">
          <option :value="50">50</option><option :value="100">100</option>
          <option :value="200">200</option><option :value="500">500</option>
        </select>
      </div>
      <span class="muted">{{ entries.length }} shown · {{ meta.servers_queried }} servers</span>
    </div>

    <div class="card">
      <table class="qlog">
        <thead><tr>
          <th>Time</th><th>Server</th><th>Client</th><th>Domain</th><th>Type</th>
          <th>Result</th><th>Answer</th><th>Upstream</th><th style="text-align:right">ms</th>
        </tr></thead>
        <tbody>
          <tr v-for="(e, i) in entries" :key="i">
            <td class="muted" style="white-space:nowrap">{{ fmt(e.time) }}</td>
            <td class="clip" :title="e.server">{{ e.server }}</td>
            <td class="clip" :class="{ mono: !e.client_name }"
                :title="e.client_name ? `${e.client_name} (${e.client})` : e.client">
              {{ e.client_name || e.client }}
            </td>
            <td class="mono domain" :title="e.question">
              <strong>{{ e.question }}</strong>
              <span v-if="e.cached" class="badge offline" style="margin-left:6px">cached</span>
            </td>
            <td class="muted">{{ e.type }}</td>
            <td style="white-space:nowrap">
              <span v-if="e.blocked" class="badge error">blocked</span>
              <span v-else-if="e.reason && e.reason.startsWith('Rewrite')" class="badge global">rewritten</span>
              <span v-else class="badge synced">ok</span>
            </td>
            <td class="mono muted clip" :title="e.answer">{{ e.answer }}</td>
            <td class="mono muted clip" :title="e.upstream">{{ e.upstream }}</td>
            <td class="muted" style="text-align:right">{{ e.elapsed_ms ? Number(e.elapsed_ms).toFixed(1) : '' }}</td>
          </tr>
          <tr v-if="!entries.length"><td colspan="9" class="empty">{{ loading ? 'Loading…' : 'No queries match.' }}</td></tr>
        </tbody>
      </table>
    </div>
    <p class="hint" style="margin-top:10px">
      Combined view shows the most recent {{ limit }} queries from each selected server, merged by time.
      Hover a truncated cell to see its full value.
    </p>
  </div>
</template>

<style scoped>
/* Fixed layout keeps long answers/upstreams from blowing out the Domain column. */
.qlog { table-layout: fixed; width: 100%; }
.qlog th, .qlog td { overflow: hidden; }
.qlog .clip {
  max-width: 0;            /* fixed layout distributes by the col widths below */
  white-space: nowrap;
  text-overflow: ellipsis;
}
/* Domain is the column you most want to read — let it wrap rather than clip. */
.qlog .domain {
  white-space: normal;
  word-break: break-all;
}
/* Column widths: prioritise Domain, cap the noisy columns. */
.qlog th:nth-child(1), .qlog td:nth-child(1) { width: 130px; }  /* Time */
.qlog th:nth-child(2), .qlog td:nth-child(2) { width: 110px; }  /* Server */
.qlog th:nth-child(3), .qlog td:nth-child(3) { width: 130px; }  /* Client */
.qlog th:nth-child(4), .qlog td:nth-child(4) { width: 34%; }    /* Domain */
.qlog th:nth-child(5), .qlog td:nth-child(5) { width: 56px; }   /* Type */
.qlog th:nth-child(6), .qlog td:nth-child(6) { width: 92px; }   /* Result */
.qlog th:nth-child(7), .qlog td:nth-child(7) { width: 30%; }    /* Answer */
.qlog th:nth-child(8), .qlog td:nth-child(8) { width: 22%; }    /* Upstream */
.qlog th:nth-child(9), .qlog td:nth-child(9) { width: 52px; }   /* ms */
</style>
