<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'
import ActionMenu from '../components/ActionMenu.vue'
import ZoneBadge from '../components/ZoneBadge.vue'

const auth = useAuth()
const agents = ref([])
const zones = ref([])
const msg = ref('')
const error = ref('')
const busyId = ref(null)
// The agent build this control plane serves (null while unknown, false when
// there is none — an API-only run has no AGENT_BIN_DIR).
const manifest = ref(null)

// Logs modal
const logsTarget = ref(null)
const logsService = ref('agent')
const logsLines = ref(200)
const logs = ref(null)
const logsError = ref('')
const logsLoading = ref(false)

// Restart modal
const restartTarget = ref(null)
const restartService = ref('adguard')
const restarting = ref(false)

const SERVICES = ['agent', 'adguard', 'dnsdist', 'keepalived']

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || 'Unzoned'

const sorted = computed(() =>
  [...agents.value].sort((a, b) => zoneName(a.zone_id).localeCompare(zoneName(b.zone_id)) || a.name.localeCompare(b.name))
)

async function load() {
  const [a, z] = await Promise.all([api.get('/agents'), api.get('/zones')])
  agents.value = a.data
  zones.value = z.data
}

async function loadManifest() {
  try {
    manifest.value = (await api.get('/agents/download/manifest')).data
  } catch {
    manifest.value = false
  }
}

// ---- health helpers -------------------------------------------------------
const GB = 1024 ** 3
function gb(bytes) { return bytes == null ? '—' : (bytes / GB).toFixed(bytes / GB >= 10 ? 0 : 1) + ' GB' }
function load1(a) { const l = a.health?.load; return Array.isArray(l) && l.length ? Number(l[0]).toFixed(2) : null }
function memPct(a) {
  const m = a.health?.mem
  if (!m || !m.total_bytes) return null
  return Math.round(((m.total_bytes - m.available_bytes) / m.total_bytes) * 100)
}
function rootDisk(a) {
  const d = a.health?.disks
  if (!Array.isArray(d) || !d.length) return null
  return d.find((x) => x.path === '/') || d[0]
}
function diskPct(d) { return d && d.total_bytes ? Math.round(((d.total_bytes - d.free_bytes) / d.total_bytes) * 100) : null }
function meterClass(pct) { return pct == null ? '' : pct >= 90 ? 'crit' : pct >= 75 ? 'warn' : '' }

function certDays(a) {
  if (!a.cert_not_after) return null
  return Math.floor((new Date(a.cert_not_after) - Date.now()) / 86400000)
}
function certClass(a) {
  const d = certDays(a)
  if (d == null) return 'muted'
  return d < 30 ? 'badge error' : d < 120 ? 'badge drift' : 'badge synced'
}

function serviceState(a, name) {
  const s = a.health?.services?.[name]
  if (!s || !s.present) return null
  return s
}

function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

// ---- actions ---------------------------------------------------------------
async function refresh(a) {
  busyId.value = a.id
  error.value = ''
  try {
    const { data } = await api.post(`/agents/${a.id}/refresh`)
    agents.value = agents.value.map((x) => (x.id === a.id ? data : x))
    msg.value = `${data.name}: refreshed.`
  } catch (e) {
    error.value = `${a.name}: ${e.response?.data?.detail || 'refresh failed'}`
  } finally {
    busyId.value = null
  }
}

function openLogs(a, service = 'agent') {
  logsTarget.value = a
  logsService.value = service
  logs.value = null
  logsError.value = ''
  fetchLogs()
}

async function fetchLogs() {
  if (!logsTarget.value) return
  logsLoading.value = true
  logsError.value = ''
  try {
    const { data } = await api.get(`/agents/${logsTarget.value.id}/logs`, {
      params: { service: logsService.value, lines: logsLines.value },
    })
    logs.value = data.lines || []
  } catch (e) {
    logsError.value = e.response?.data?.detail || 'Could not read logs'
  } finally {
    logsLoading.value = false
  }
}

function openRestart(a) {
  restartTarget.value = a
  restartService.value = a.roles?.includes('adguard') ? 'adguard' : (a.roles?.[0] || 'adguard')
}

async function runRestart() {
  restarting.value = true
  error.value = ''
  try {
    const { data } = await api.post(`/agents/${restartTarget.value.id}/services/${restartService.value}/restart`)
    msg.value = `${restartTarget.value.name}: ${restartService.value} restarted${data.message ? ' — ' + data.message : ''}.`
    restartTarget.value = null
  } catch (e) {
    error.value = e.response?.data?.detail || 'Restart failed'
  } finally {
    restarting.value = false
  }
}

async function updateAgent(a) {
  const target = manifest.value?.version ? ` to ${manifest.value.version}` : ''
  if (!confirm(`Update the agent on ${a.name}${target}? The agent restarts; AdGuard and the balancer keep running.`)) return
  busyId.value = a.id
  error.value = ''
  try {
    const { data } = await api.post(`/agents/${a.id}/update`)
    agents.value = agents.value.map((x) => (x.id === a.id ? data : x))
    msg.value = `${data.name}: agent update started — it restarts and reports its new version on the next refresh.`
  } catch (e) {
    error.value = `${a.name}: ${e.response?.data?.detail || 'agent update failed'}`
  } finally {
    busyId.value = null
  }
}

async function renewCert(a) {
  if (!confirm(`Issue a new certificate for ${a.name}? The agent swaps it live; nothing restarts.`)) return
  busyId.value = a.id
  error.value = ''
  try {
    const { data } = await api.post(`/agents/${a.id}/renew-cert`)
    agents.value = agents.value.map((x) => (x.id === a.id ? data : x))
    msg.value = `${data.name}: certificate renewed, valid until ${fmt(data.cert_not_after)}.`
  } catch (e) {
    error.value = `${a.name}: ${e.response?.data?.detail || 'renewal failed'}`
  } finally {
    busyId.value = null
  }
}

async function remove(a) {
  const refs = (a.server_ids?.length || 0) + (a.load_balancer_ids?.length || 0)
  if (!confirm(`Delete host "${a.name}"? The agent on the box keeps running; this only forgets it here.`)) return
  try {
    await api.delete(`/agents/${a.id}`)
    await load()
  } catch (e) {
    if (e.response?.status === 409) {
      if (!confirm(`${a.name} still has ${refs || 'linked'} server(s)/balancer(s). Detach them and delete anyway?`)) return
      try { await api.delete(`/agents/${a.id}`, { params: { force: true } }); await load() }
      catch (e2) { error.value = e2.response?.data?.detail || 'Delete failed' }
    } else {
      error.value = e.response?.data?.detail || 'Delete failed'
    }
  }
}

onMounted(() => { load(); loadManifest() })
</script>

<template>
  <div class="topbar">
    <h1>Hosts</h1>
    <div class="flex" style="gap:12px;align-items:center">
      <span v-if="manifest && manifest.version" class="muted" title="Agent build served to new and updating hosts">
        Agent available: <span class="mono">{{ manifest.version }}</span>
      </span>
      <span v-else-if="manifest === false" class="muted" title="AGENT_BIN_DIR is empty on this control plane">
        No agent build on this control plane
      </span>
      <router-link v-if="auth.isEditor" class="btn btn-primary" to="/provision">+ Provision a host</router-link>
    </div>
  </div>
  <div class="content">
    <div v-if="msg" class="alert alert-success" @click="msg = ''">{{ msg }}</div>
    <div v-if="error" class="alert alert-error" @click="error = ''">{{ error }}</div>
    <div class="card">
      <table>
        <thead><tr>
          <th>Status</th><th>Host</th><th>Zone</th><th>Roles</th><th>Agent</th>
          <th>Load</th><th>Memory</th><th>Disk</th><th>Certificate</th><th>Last seen</th><th></th>
        </tr></thead>
        <tbody>
          <tr v-for="a in sorted" :key="a.id">
            <td><span class="badge" :class="a.status"><span class="dot"></span>{{ a.status }}</span></td>
            <td>
              <strong>{{ a.name }}</strong>
              <div class="muted mono">{{ a.address }}:{{ a.port }}<span v-if="a.hostname && a.hostname !== a.name"> · {{ a.hostname }}</span></div>
              <div v-if="a.last_error" class="hint" style="color:var(--red)">{{ a.last_error }}</div>
            </td>
            <td><ZoneBadge :id="a.zone_id" :label="zoneName(a.zone_id)" /></td>
            <td>
              <div class="badges">
                <span v-for="r in (a.roles || [])" :key="r" class="badge" :class="'role-' + r"
                      :title="serviceState(a, r) ? (serviceState(a, r).running ? 'running' : 'not running') + (serviceState(a, r).version ? ' · ' + serviceState(a, r).version : '') : ''">
                  {{ r }}<span v-if="serviceState(a, r) && !serviceState(a, r).running" style="margin-left:4px">⏸</span>
                </span>
                <span v-if="!(a.roles || []).length" class="muted">—</span>
              </div>
            </td>
            <td>
              <span class="mono">{{ a.version || '—' }}</span>
              <span v-if="a.update_available" class="badge drift" style="margin-left:6px"
                    :title="manifest && manifest.version ? `Update available: ${manifest.version}` : 'Update available'">update available</span>
              <div class="hint">{{ a.os }}/{{ a.arch }}</div>
              <div v-if="a.update_error" class="hint" style="color:var(--red)">{{ a.update_error }}</div>
              <div v-else-if="a.update_attempted_at" class="hint">update attempted {{ fmt(a.update_attempted_at) }}</div>
            </td>
            <td>
              <span v-if="load1(a) != null">{{ load1(a) }}</span>
              <span v-else class="muted">—</span>
            </td>
            <td>
              <template v-if="memPct(a) != null">
                <span class="meter" :class="meterClass(memPct(a))"><span :style="{ width: memPct(a) + '%' }"></span></span>
                <div class="hint">{{ memPct(a) }}% of {{ gb(a.health.mem.total_bytes) }}</div>
              </template>
              <span v-else class="muted">—</span>
            </td>
            <td>
              <template v-if="rootDisk(a)">
                <span class="meter" :class="meterClass(diskPct(rootDisk(a)))"><span :style="{ width: diskPct(rootDisk(a)) + '%' }"></span></span>
                <div class="hint">{{ gb(rootDisk(a).free_bytes) }} free on {{ rootDisk(a).path }}</div>
              </template>
              <span v-else class="muted">—</span>
            </td>
            <td>
              <span v-if="certDays(a) != null" :class="certClass(a)">{{ certDays(a) < 0 ? 'expired' : certDays(a) + ' d' }}</span>
              <span v-else class="muted">—</span>
              <div class="hint">{{ fmt(a.cert_not_after) }}</div>
            </td>
            <td class="muted">{{ fmt(a.last_seen) }}</td>
            <td class="row-actions">
              <button class="btn btn-sm" :disabled="busyId === a.id" @click="refresh(a)">
                <span v-if="busyId === a.id" class="spinner" style="border-color:rgba(0,0,0,.2);border-top-color:var(--text)"></span>
                <span>Refresh</span>
              </button>
              <ActionMenu>
                <button class="menu-item" @click="openLogs(a)">View logs</button>
                <template v-if="auth.isEditor">
                  <button class="menu-item" @click="openRestart(a)">Restart a service</button>
                  <button class="menu-item" :disabled="busyId === a.id || manifest === false" @click="updateAgent(a)"
                          :title="manifest === false ? 'No agent build on this control plane' : 'Replaces the agent binary and restarts it'">
                    Update agent{{ a.update_available && manifest && manifest.version ? ` to ${manifest.version}` : '' }}
                  </button>
                  <button class="menu-item" @click="renewCert(a)">Renew certificate</button>
                </template>
                <template v-if="auth.isAdmin">
                  <div class="menu-divider"></div>
                  <button class="menu-item danger" @click="remove(a)">Delete</button>
                </template>
              </ActionMenu>
            </td>
          </tr>
          <tr v-if="!agents.length">
            <td colspan="11" class="empty">
              No hosts yet. A host appears here once its agent enrolls — generate an install command under
              <router-link to="/provision">Provisioning</router-link>, run it on the box, and the agent registers itself.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <Modal v-if="logsTarget" :title="`Logs — ${logsTarget.name}`" @close="logsTarget = null">
    <div class="flex" style="gap:10px;margin-bottom:12px">
      <select v-model="logsService" style="width:auto" @change="fetchLogs">
        <option v-for="s in SERVICES" :key="s" :value="s">{{ s }}</option>
      </select>
      <select v-model.number="logsLines" style="width:auto" @change="fetchLogs">
        <option :value="100">100 lines</option>
        <option :value="200">200 lines</option>
        <option :value="500">500 lines</option>
        <option :value="2000">2000 lines</option>
      </select>
      <button class="btn btn-sm" :disabled="logsLoading" @click="fetchLogs">{{ logsLoading ? 'Loading…' : 'Reload' }}</button>
    </div>
    <div v-if="logsError" class="alert alert-error">{{ logsError }}</div>
    <pre v-else-if="logs" class="log-box mono">{{ logs.length ? logs.join('\n') : '(no output)' }}</pre>
    <div v-else class="muted">Loading…</div>
    <template #footer>
      <button class="btn btn-primary" @click="logsTarget = null">Close</button>
    </template>
  </Modal>

  <Modal v-if="restartTarget" :title="`Restart a service on ${restartTarget.name}`" @close="restartTarget = null">
    <div class="form-row">
      <label>Service</label>
      <select v-model="restartService">
        <option value="adguard">AdGuard Home</option>
        <option value="dnsdist">dnsdist (load balancer)</option>
        <option value="keepalived">keepalived (virtual IP)</option>
      </select>
      <div class="hint">
        Restarting AdGuard Home or dnsdist briefly stops DNS on this host. Behind a VIP the other
        balancer takes over; a lone host will drop queries for a second or two.
      </div>
    </div>
    <template #footer>
      <button class="btn" @click="restartTarget = null">Cancel</button>
      <button class="btn btn-danger" :disabled="restarting" @click="runRestart">
        <span v-if="restarting" class="spinner"></span><span>Restart</span>
      </button>
    </template>
  </Modal>
</template>
