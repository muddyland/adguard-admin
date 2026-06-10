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

// Column definitions drive both the <colgroup> and header; widths (px) are
// user-resizable and persisted. `align` right-aligns the ms column header.
const COLUMNS = [
  { key: 'time', label: 'Time', w: 130 },
  { key: 'server', label: 'Server', w: 90 },
  { key: 'client', label: 'Client', w: 130 },
  { key: 'domain', label: 'Domain', w: 280 },
  { key: 'type', label: 'Type', w: 60 },
  { key: 'result', label: 'Result', w: 90 },
  { key: 'answer', label: 'Answer', w: 220 },
  { key: 'upstream', label: 'Upstream', w: 200 },
  { key: 'ms', label: 'ms', w: 56, align: 'right' },
]
const STORAGE_KEY = 'qlog-col-widths-v1'

function loadWidths() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY))
    if (Array.isArray(saved) && saved.length === COLUMNS.length) return saved
  } catch { /* ignore bad/legacy storage */ }
  return COLUMNS.map((c) => c.w)
}
const widths = ref(loadWidths())
const tableWidth = computed(() => widths.value.reduce((a, b) => a + b, 0))

let resizing = null
function startResize(e, i) {
  const x = e.touches ? e.touches[0].clientX : e.clientX
  resizing = { i, startX: x, startW: widths.value[i] }
  window.addEventListener('mousemove', onResize)
  window.addEventListener('mouseup', stopResize)
  window.addEventListener('touchmove', onResize, { passive: false })
  window.addEventListener('touchend', stopResize)
  document.body.classList.add('col-resizing')
  e.preventDefault()
}
function onResize(e) {
  if (!resizing) return
  const x = e.touches ? e.touches[0].clientX : e.clientX
  const next = widths.value.slice()
  next[resizing.i] = Math.max(44, resizing.startW + (x - resizing.startX))
  widths.value = next
  if (e.cancelable) e.preventDefault()
}
function stopResize() {
  resizing = null
  window.removeEventListener('mousemove', onResize)
  window.removeEventListener('mouseup', stopResize)
  window.removeEventListener('touchmove', onResize)
  window.removeEventListener('touchend', stopResize)
  document.body.classList.remove('col-resizing')
  localStorage.setItem(STORAGE_KEY, JSON.stringify(widths.value))
}
function resetWidths() {
  widths.value = COLUMNS.map((c) => c.w)
  localStorage.removeItem(STORAGE_KEY)
}

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
      <span class="muted">
        {{ entries.length }} shown · {{ meta.servers_queried }} servers
        <button class="link-btn" @click="resetWidths">reset columns</button>
      </span>
    </div>

    <div class="card qlog-scroll">
      <table class="qlog" :style="{ width: tableWidth + 'px' }">
        <colgroup>
          <col v-for="(c, i) in COLUMNS" :key="c.key" :style="{ width: widths[i] + 'px' }" />
        </colgroup>
        <thead><tr>
          <th v-for="(c, i) in COLUMNS" :key="c.key" :style="c.align ? { textAlign: c.align } : null">
            <span>{{ c.label }}</span>
            <span v-if="i < COLUMNS.length - 1" class="col-resizer"
                  @mousedown="startResize($event, i)" @touchstart="startResize($event, i)"></span>
          </th>
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
      Drag a column edge to resize; hover a truncated cell to see its full value.
    </p>
  </div>
</template>

<style scoped>
.qlog-scroll { overflow-x: auto; }
/* Fixed layout + explicit col widths: long answers/upstreams clip instead of
   blowing out the table, and column widths are driven by the <colgroup>. */
.qlog { table-layout: fixed; }
.qlog th, .qlog td { overflow: hidden; }
.qlog th { position: relative; }
.qlog .clip {
  white-space: nowrap;
  text-overflow: ellipsis;
}
/* Domain is the column you most want to read — let it wrap rather than clip. */
.qlog .domain {
  white-space: normal;
  overflow-wrap: anywhere;
}
/* Drag handle on the right edge of each header. */
.col-resizer {
  position: absolute;
  top: 0;
  right: 0;
  width: 8px;
  height: 100%;
  cursor: col-resize;
  user-select: none;
}
.col-resizer:hover { background: var(--accent, #67b279); opacity: 0.4; }
.link-btn {
  background: none;
  border: none;
  color: var(--accent, #67b279);
  cursor: pointer;
  font: inherit;
  padding: 0;
  margin-left: 10px;
}
.link-btn:hover { text-decoration: underline; }
</style>
