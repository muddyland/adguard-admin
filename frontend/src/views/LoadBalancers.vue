<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'
import ActionMenu from '../components/ActionMenu.vue'
import ZoneBadge from '../components/ZoneBadge.vue'

const auth = useAuth()
const lbs = ref([])
const zones = ref([])
const agents = ref([])
const msg = ref('')
const error = ref('')
const busyId = ref(null)

// Selected balancer (detail panel) and its live data
const selectedId = ref(null)
const live = ref(null)          // { dnsdist, keepalived } fresh from the agent
const liveError = ref('')
const liveAt = ref(null)
let pollTimer = null

// Create / edit modal
const showModal = ref(false)
const editing = ref(null)
const form = ref({})
const saving = ref(false)
const formError = ref('')

// Backend edit modal
const backendTarget = ref(null)   // { lb, backend }
const backendForm = ref({})
const backendError = ref('')

// Logs modal (dnsdist / keepalived on the balancer's host)
const logsTarget = ref(null)
const logsService = ref('dnsdist')
const logs = ref(null)
const logsError = ref('')
const logsLoading = ref(false)

const POLICIES = [
  { value: 'leastOutstanding', label: 'Least outstanding (recommended)' },
  { value: 'roundrobin', label: 'Round robin' },
  { value: 'wrandom', label: 'Weighted random' },
  { value: 'whashed', label: 'Weighted hash (same name → same backend)' },
  { value: 'firstAvailable', label: 'First available (ordered failover)' },
]
const DEFAULT_ACL = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']
const MODES = [
  { value: 'dnsdist', label: 'dnsdist proxy', hint: 'per-query stats, works across VLANs; backends see the balancer\'s address' },
  { value: 'ipvs', label: 'IPVS direct routing', hint: 'kernel L4, backends see the real client; needs a zone VIP and one L2 segment' },
]
const ALGOS = [
  { value: 'wlc', label: 'Weighted least-connection (recommended)' },
  { value: 'rr', label: 'Round robin' },
  { value: 'wrr', label: 'Weighted round robin' },
  { value: 'lc', label: 'Least-connection' },
  { value: 'sh', label: 'Source hash (same client → same backend)' },
]
const isIpvs = (lb) => lb?.mode === 'ipvs'

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || 'Unzoned'
const zoneOf = (lb) => zones.value.find((z) => z.id === lb.zone_id)
const agentOf = (id) => agents.value.find((a) => a.id === id)
const agentName = (id) => agentOf(id)?.name || (id ? `host #${id}` : '—')

const selected = computed(() => lbs.value.find((l) => l.id === selectedId.value) || null)

async function load() {
  const [l, z] = await Promise.all([api.get('/load-balancers'), api.get('/zones')])
  lbs.value = l.data
  zones.value = z.data
  try { agents.value = (await api.get('/agents')).data } catch { agents.value = [] }
}

// ---- derived per-row numbers (from the stored snapshot in the list) -------
function backendsOf(lb) { return lb.backends || [] }
function upCount(lb) { return backendsOf(lb).filter((b) => b.live?.state === 'up' && !b.live?.drained).length }
function downCount(lb) { return backendsOf(lb).filter((b) => b.live?.state === 'down').length }
function drainedCount(lb) { return backendsOf(lb).filter((b) => b.live?.drained).length }
function qpsOf(lb) {
  const bs = backendsOf(lb).filter((b) => b.live && b.live.qps != null)
  if (!bs.length) return null
  return bs.reduce((n, b) => n + Number(b.live.qps || 0), 0)
}
function vipOwner(lb) { return !!lb.keepalived_state?.vip_owner }
function ownerOf(zone) {
  const lb = lbs.value.find((l) => l.zone_id === zone.id && vipOwner(l))
  return lb ? agentName(lb.agent_id) : null
}
function num(n) { return n == null ? '—' : Number(n).toLocaleString() }
function fixed(n, d = 1) { return n == null ? '—' : Number(n).toFixed(d) }
function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

// ---- detail panel: merge the stored snapshot with the fresh agent state ----
function addrKey(address, port) {
  if (!address) return ''
  const a = address.includes(':') && !address.startsWith('[') ? `[${address}]` : address
  return port != null ? `${a}:${port}` : a
}

const detailIpvs = computed(() => live.value?.keepalived?.ipvs || selected.value?.keepalived_state?.ipvs || null)

const detailBackends = computed(() => {
  const lb = selected.value
  if (!lb) return []
  if (isIpvs(lb)) return ipvsBackends(lb)
  const fresh = live.value?.dnsdist?.backends || []
  const byAddr = new Map(fresh.map((f) => [f.address, f]))
  const byName = new Map(fresh.map((f) => [f.name, f]))
  const rows = backendsOf(lb).map((b) => {
    // The control plane names dnsdist backends "<server-name>-<server id>"; match on
    // that first, then on address, then on the bare server name.
    const f = fresh.find((x) => typeof x.name === 'string' && x.name.endsWith(`-${b.server_id}`))
      || byAddr.get(addrKey(b.address, b.port)) || byName.get(b.server_name) || null
    const l = f
      ? { state: f.state, drained: f.drained, qps: f.qps, queries: f.queries, responses: f.responses,
          latency_ms: f.latency_ms, outstanding: f.outstanding, drop_rate: f.drop_rate,
          send_errors: f.send_errors, health_failures: f.health_failures }
      : (b.live || null)
    return { ...b, live: l }
  })
  const total = rows.reduce((n, r) => n + Number(r.live?.queries || 0), 0)
  return rows.map((r) => ({ ...r, share: total ? (Number(r.live?.queries || 0) / total) * 100 : 0 }))
})

// IPVS mode: live numbers come from keepalived's view of the kernel table.
function ipvsBackends(lb) {
  const fresh = detailIpvs.value?.backends || []
  const byAddr = new Map(fresh.map((f) => [addrKey(f.address, f.port), f]))
  const rows = backendsOf(lb).map((b) => {
    const f = fresh.find((x) => typeof x.name === 'string' && x.name.endsWith(`-${b.server_id}`))
      || byAddr.get(addrKey(b.address, b.port)) || null
    const l = f
      ? { state: f.state, drained: f.drained, qps: f.in_pps, queries: f.in_pkts, conns: f.conns,
          active_conns: f.active_conns, inactive_conns: f.inactive_conns, in_bytes: f.in_bytes, cps: f.cps,
          weight: f.weight }
      : (b.live || null)
    return { ...b, live: l }
  })
  // Packet counters are null when the agent read the table from /proc (no
  // ipvsadm); a null share keeps the bar empty rather than claiming 0%.
  const total = rows.reduce((n, r) => n + Number(r.live?.queries || 0), 0)
  return rows.map((r) => ({
    ...r,
    share: r.live?.queries == null ? null : (total ? (Number(r.live.queries) / total) * 100 : 0),
  }))
}

// Diagnostics the agent attaches to the keepalived ipvs block (older agents send none).
const ipvsDiag = computed(() => detailIpvs.value?.diagnostics || null)
const DIAG_ITEMS = [
  { key: 'ipvsadm', label: 'ipvsadm installed' },
  { key: 'module_loaded', label: 'ip_vs kernel module loaded' },
  { key: 'config_has_virtual_servers', label: 'virtual_server in keepalived config' },
  { key: 'keepalived_running', label: 'keepalived running' },
]
// One hint for "no virtual server programmed", in the contract's priority order.
const ipvsHint = computed(() => {
  const d = ipvsDiag.value
  if (!d) return 'keepalived has not applied the IPVS configuration on this host yet.'
  if (d.module_loaded === false) {
    if (d.container) {
      // A container cannot load kernel modules; the node that runs it must.
      return `This host is a ${d.container} container, so it cannot load kernel modules itself. On the node that runs it: `
        + '`modprobe ip_vs ip_vs_wlc ip_vs_rr ip_vs_wrr ip_vs_lc ip_vs_sh` and persist them in /etc/modules-load.d/ipvs.conf, then restart keepalived here.'
    }
    return `the ip_vs kernel module is not loaded${d.modprobe_error ? ` (modprobe error: ${d.modprobe_error})` : ''}; check that the kernel ships it.`
  }
  if (d.ipvsadm === false) return 'ipvsadm is not installed; the agent installs it with keepalived, see the agent log.'
  if (d.config_has_virtual_servers === false) return 'the rendered keepalived config has no virtual_server block: the zone VIP or mode changed and the host has not converged yet.'
  if (d.keepalived_running === false) return 'keepalived is not running on this host; see its log.'
  return 'keepalived is running and the module is loaded but no service is programmed; check the keepalived log for the virtual_server section.'
})

const detailStats = computed(() => live.value?.dnsdist?.stats || selected.value?.state?.stats || null)
const detailFrontends = computed(() => live.value?.dnsdist?.frontends || selected.value?.state?.frontends || [])
const detailDnsdist = computed(() => live.value?.dnsdist || selected.value?.state || null)
const detailKeepalived = computed(() => live.value?.keepalived || selected.value?.keepalived_state || null)
const cacheHitRate = computed(() => {
  const s = detailStats.value
  if (!s) return null
  const hits = Number(s['cache-hits'] || 0), misses = Number(s['cache-misses'] || 0)
  return hits + misses ? Math.round((hits / (hits + misses)) * 100) : 0
})
function uptime(s) {
  if (s == null) return '—'
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`
}
function liveBadge(l) {
  if (!l || !l.state) return { cls: 'nodata', text: 'no data' }
  if (l.drained) return { cls: 'drained', text: 'drained' }
  return { cls: l.state === 'up' ? 'up' : 'down', text: l.state }
}

async function pollLive() {
  if (!selectedId.value) return
  const id = selectedId.value
  try {
    const { data } = await api.get(`/load-balancers/${id}/state`)
    if (selectedId.value !== id) return
    live.value = data
    liveAt.value = new Date()
    liveError.value = ''
  } catch (e) {
    if (selectedId.value !== id) return
    liveError.value = e.response?.data?.detail || 'The host did not answer; showing the last snapshot.'
  }
}

function select(lb) {
  if (selectedId.value === lb.id) { selectedId.value = null; return }
  selectedId.value = lb.id
  live.value = null
  liveError.value = ''
}

watch(selectedId, (id) => {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
  if (id != null) {
    pollLive()
    pollTimer = setInterval(pollLive, 5000)
  }
})
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

// ---- actions ---------------------------------------------------------------
async function syncNow(lb) {
  busyId.value = lb.id
  error.value = ''
  try {
    const { data } = await api.post(`/load-balancers/${lb.id}/sync`)
    lbs.value = lbs.value.map((x) => (x.id === lb.id ? data : x))
    msg.value = `${data.name}: ${data.in_sync ? 'in sync' : (data.last_error || 'reconcile started')}.`
  } catch (e) {
    error.value = `${lb.name}: ${e.response?.data?.detail || 'sync failed'}`
  } finally { busyId.value = null }
}

async function restart(lb) {
  const svc = isIpvs(lb) ? 'keepalived' : 'dnsdist'
  if (!confirm(`Restart ${svc} on ${agentName(lb.agent_id)}? Queries to this balancer drop for a second or two.`)) return
  busyId.value = lb.id
  error.value = ''
  try {
    await api.post(`/load-balancers/${lb.id}/restart`)
    msg.value = `${lb.name}: ${svc} restarted.`
  } catch (e) {
    error.value = `${lb.name}: ${e.response?.data?.detail || 'restart failed'}`
  } finally { busyId.value = null }
}

async function drain(lb, b, undrain = false) {
  error.value = ''
  try {
    await api.post(`/load-balancers/${lb.id}/backends/${b.server_id}/${undrain ? 'undrain' : 'drain'}`)
    msg.value = `${b.server_name}: ${undrain ? 'back in rotation' : 'drained (no new queries until undrained)'}.`
    await pollLive()
    await load()
  } catch (e) {
    error.value = `${b.server_name}: ${e.response?.data?.detail || 'request failed'}`
  }
}

function openBackend(lb, b) {
  backendTarget.value = { lb, backend: b }
  backendForm.value = { enabled: b.enabled, weight: b.weight, order: b.order }
  backendError.value = ''
}

async function saveBackend() {
  backendError.value = ''
  const { lb, backend } = backendTarget.value
  try {
    const { data } = await api.put(`/load-balancers/${lb.id}/backends/${backend.server_id}`, backendForm.value)
    lbs.value = lbs.value.map((x) => (x.id === lb.id ? data : x))
    backendTarget.value = null
    msg.value = `${backend.server_name}: backend settings saved; applied on the next sync.`
  } catch (e) {
    backendError.value = e.response?.data?.detail || 'Save failed'
  }
}

async function remove(lb) {
  if (!confirm(`Delete load balancer "${lb.name}"? ${isIpvs(lb) ? 'keepalived' : 'dnsdist'} on the host is stopped on the next sync; the host itself stays.`)) return
  try {
    await api.delete(`/load-balancers/${lb.id}`)
    if (selectedId.value === lb.id) selectedId.value = null
    await load()
  } catch (e) { error.value = e.response?.data?.detail || 'Delete failed' }
}

function openLogs(lb, service = 'dnsdist') {
  logsTarget.value = lb
  logsService.value = isIpvs(lb) && service === 'dnsdist' ? 'keepalived' : service
  logs.value = null
  logsError.value = ''
  fetchLogs()
}
async function fetchLogs() {
  if (!logsTarget.value) return
  logsLoading.value = true
  logsError.value = ''
  try {
    const { data } = await api.get(`/agents/${logsTarget.value.agent_id}/logs`, { params: { service: logsService.value, lines: 200 } })
    logs.value = data.lines || []
  } catch (e) {
    logsError.value = e.response?.data?.detail || 'Could not read logs'
  } finally { logsLoading.value = false }
}

// ---- create / edit -----------------------------------------------------------
function blankForm() {
  return {
    name: '', zone_id: null, agent_id: null, enabled: true, mode: 'dnsdist', ipvs_algo: 'wlc',
    install_method: 'docker', image: 'powerdns/dnsdist-20:2.0.8',
    listen_text: '0.0.0.0:53', policy: 'leastOutstanding', ecs: true,
    cache_enabled: false, cache_max_entries: 100000,
    hc_name: 'a.root-servers.net.', hc_interval_s: 1, hc_max_failures: 3, hc_rise: 2, hc_mode: 'auto',
    acl_text: DEFAULT_ACL.join('\n'), vrrp_priority: 100, vip_interface: '',
  }
}
function openCreate() {
  editing.value = null
  form.value = blankForm()
  formError.value = ''
  showModal.value = true
}
function openEdit(lb) {
  editing.value = lb
  form.value = {
    name: lb.name, zone_id: lb.zone_id, agent_id: lb.agent_id, enabled: lb.enabled,
    mode: lb.mode || 'dnsdist', ipvs_algo: lb.ipvs_algo || 'wlc',
    install_method: lb.install_method || 'docker', image: lb.image || '',
    listen_text: (lb.listen_addresses || []).join('\n'), policy: lb.policy || 'leastOutstanding', ecs: !!lb.ecs,
    cache_enabled: !!lb.cache_enabled, cache_max_entries: lb.cache_max_entries ?? 100000,
    hc_name: lb.hc_name || 'a.root-servers.net.', hc_interval_s: lb.hc_interval_s ?? 1,
    hc_max_failures: lb.hc_max_failures ?? 3, hc_rise: lb.hc_rise ?? 2, hc_mode: lb.hc_mode || 'auto',
    acl_text: (lb.acl || []).join('\n'), vrrp_priority: lb.vrrp_priority ?? 100, vip_interface: lb.vip_interface || '',
  }
  formError.value = ''
  showModal.value = true
}
const lines = (t) => (t || '').split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
const formZone = computed(() => zones.value.find((z) => z.id === form.value.zone_id))
const formIpvs = computed(() => form.value.mode === 'ipvs')
// IPVS mode has no address of its own: the VIP *is* the service, so it is required.
const formMissingVip = computed(() => formIpvs.value && !!form.value.zone_id && !formZone.value?.vip)
const agentChoices = computed(() => {
  // Hosts in the chosen zone first, then the rest, so a mismatch is a visible choice.
  const z = form.value.zone_id
  return [...agents.value].sort((a, b) => (a.zone_id === z ? 0 : 1) - (b.zone_id === z ? 0 : 1) || a.name.localeCompare(b.name))
})

async function save() {
  formError.value = ''
  saving.value = true
  const f = form.value
  const payload = f.mode === 'ipvs'
    ? {
        name: f.name, zone_id: f.zone_id, agent_id: f.agent_id, enabled: f.enabled,
        mode: 'ipvs', ipvs_algo: f.ipvs_algo,
        hc_interval_s: Number(f.hc_interval_s) || 2, hc_max_failures: Number(f.hc_max_failures) || 2,
        vrrp_priority: Number(f.vrrp_priority) || 100, vip_interface: f.vip_interface || '',
      }
    : {
        name: f.name, zone_id: f.zone_id, agent_id: f.agent_id, enabled: f.enabled,
        mode: 'dnsdist', ipvs_algo: f.ipvs_algo,
        install_method: f.install_method, image: f.image || undefined,
        listen_addresses: lines(f.listen_text), policy: f.policy, ecs: f.ecs,
        cache_enabled: f.cache_enabled, cache_max_entries: Number(f.cache_max_entries) || 100000,
        hc_name: f.hc_name, hc_interval_s: Number(f.hc_interval_s) || 1,
        hc_max_failures: Number(f.hc_max_failures) || 3, hc_rise: Number(f.hc_rise) || 2, hc_mode: f.hc_mode,
        acl: lines(f.acl_text), vrrp_priority: Number(f.vrrp_priority) || 100, vip_interface: f.vip_interface || '',
      }
  try {
    if (editing.value) {
      const { data } = await api.patch(`/load-balancers/${editing.value.id}`, payload)
      lbs.value = lbs.value.map((x) => (x.id === data.id ? data : x))
    } else {
      await api.post('/load-balancers', payload)
    }
    showModal.value = false
    await load()
  } catch (e) {
    formError.value = e.response?.data?.detail || 'Save failed'
  } finally { saving.value = false }
}

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Load Balancers</h1>
    <button v-if="auth.isEditor" class="btn btn-primary" @click="openCreate">+ Add load balancer</button>
  </div>
  <div class="content">
    <div v-if="msg" class="alert alert-success" @click="msg = ''">{{ msg }}</div>
    <div v-if="error" class="alert alert-error" @click="error = ''">{{ error }}</div>

    <div class="card">
      <table>
        <thead><tr>
          <th>Status</th><th>Balancer</th><th>Zone</th><th>VIP</th><th>Backends</th><th>QPS</th><th>Sync</th><th>Last synced</th><th></th>
        </tr></thead>
        <tbody>
          <tr v-for="lb in lbs" :key="lb.id" :class="{ selected: selectedId === lb.id }" style="cursor:pointer" @click="select(lb)">
            <td><span class="badge" :class="lb.status"><span class="dot"></span>{{ lb.status }}</span></td>
            <td>
              <strong>{{ lb.name }}</strong>
              <span class="badge" :class="isIpvs(lb) ? 'mode-ipvs' : 'mode-dnsdist'" style="margin-left:6px" :title="isIpvs(lb) ? 'IPVS direct routing (keepalived)' : 'dnsdist proxy'">{{ isIpvs(lb) ? 'ipvs' : 'dnsdist' }}</span>
              <span v-if="!lb.enabled" class="badge offline" style="margin-left:6px">disabled</span>
              <div class="muted">on {{ agentName(lb.agent_id) }}<span v-if="!isIpvs(lb) && lb.state?.version"> · dnsdist {{ lb.state.version }}</span><span v-if="isIpvs(lb) && lb.keepalived_state?.version"> · keepalived {{ lb.keepalived_state.version }}</span></div>
              <div v-if="!isIpvs(lb) && lb.state && lb.state.state !== 'ready'" class="hint" :style="lb.state.state === 'error' ? 'color:var(--red)' : ''">
                {{ lb.state.state }}<span v-if="lb.state.message">: {{ lb.state.message }}</span>
              </div>
              <div v-if="isIpvs(lb) && lb.keepalived_state && lb.keepalived_state.state !== 'ready'" class="hint" :style="lb.keepalived_state.state === 'error' ? 'color:var(--red)' : ''">
                {{ lb.keepalived_state.state }}<span v-if="lb.keepalived_state.message">: {{ lb.keepalived_state.message }}</span>
              </div>
              <div v-if="lb.last_error" class="hint" style="color:var(--red)">{{ lb.last_error }}</div>
            </td>
            <td><ZoneBadge :id="lb.zone_id" :label="zoneName(lb.zone_id)" /></td>
            <td>
              <template v-if="zoneOf(lb)?.vip">
                <span class="mono">{{ zoneOf(lb).vip }}</span>
                <span v-if="vipOwner(lb)" class="badge synced" style="margin-left:6px" title="This host currently holds the virtual IP">owner</span>
                <span v-else-if="lb.keepalived_state" class="badge offline" style="margin-left:6px">standby</span>
              </template>
              <span v-else class="muted">—</span>
            </td>
            <td>
              <template v-if="backendsOf(lb).length">
                <span style="color:var(--green-dark);font-weight:600">{{ upCount(lb) }} up</span>
                <span v-if="downCount(lb)" style="color:var(--red);font-weight:600"> · {{ downCount(lb) }} down</span>
                <span v-if="drainedCount(lb)" class="muted"> · {{ drainedCount(lb) }} drained</span>
                <div class="hint">of {{ backendsOf(lb).length }}</div>
              </template>
              <span v-else class="muted">no backends in zone</span>
            </td>
            <td>{{ qpsOf(lb) == null ? '—' : fixed(qpsOf(lb)) }}</td>
            <td>
              <span v-if="lb.in_sync" class="badge synced">In sync</span>
              <span v-else class="badge drift">Drift</span>
            </td>
            <td class="muted">{{ fmt(lb.last_synced) }}</td>
            <td class="row-actions" @click.stop>
              <button class="btn btn-sm" @click="select(lb)">{{ selectedId === lb.id ? 'Hide' : 'Details' }}</button>
              <ActionMenu>
                <button v-if="!isIpvs(lb)" class="menu-item" @click="openLogs(lb, 'dnsdist')">dnsdist logs</button>
                <button class="menu-item" @click="openLogs(lb, 'keepalived')">keepalived logs</button>
                <template v-if="auth.isEditor">
                  <div class="menu-divider"></div>
                  <button class="menu-item" :disabled="busyId === lb.id" @click="syncNow(lb)">Sync now</button>
                  <button class="menu-item" :disabled="busyId === lb.id" @click="restart(lb)">Restart {{ isIpvs(lb) ? 'keepalived' : 'dnsdist' }}</button>
                  <div class="menu-divider"></div>
                  <button class="menu-item" @click="openEdit(lb)">Edit</button>
                  <button class="menu-item danger" @click="remove(lb)">Delete</button>
                </template>
              </ActionMenu>
            </td>
          </tr>
          <tr v-if="!lbs.length">
            <td colspan="9" class="empty">
              No load balancers yet. Provision a host with the <strong>load balancer</strong> role, or add one here for a
              host that is already enrolled (dnsdist proxy or IPVS direct routing). Give the zone a VIP under <router-link to="/zones">Zones</router-link> so
              clients get one address.
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Detail panel -->
    <template v-if="selected">
      <div class="card" style="margin-top:24px">
        <div class="card-header">
          <h2>{{ selected.name }} — backends</h2>
          <span class="muted" style="font-size:12px">
            <template v-if="liveAt">live · {{ liveAt.toLocaleTimeString() }}</template>
            <template v-else>loading live data…</template>
          </span>
        </div>
        <div v-if="liveError" class="alert alert-error" style="margin:12px 16px 0">{{ liveError }}</div>
        <div v-if="isIpvs(selected) && detailIpvs && detailIpvs.present === false" class="alert alert-error" style="margin:12px 16px 0">
          <div><strong>No virtual server programmed.</strong> {{ ipvsHint }}</div>
          <div v-if="detailIpvs.message" class="mono" style="margin-top:6px;font-size:12px;white-space:pre-wrap">{{ detailIpvs.message }}</div>
          <button class="btn btn-sm" style="margin-top:8px" @click="openLogs(selected, 'keepalived')">View keepalived log</button>
        </div>
        <table v-if="isIpvs(selected)">
          <thead><tr>
            <th>State</th><th>Backend</th><th>Share</th><th>Packets/s</th><th>Packets in</th><th>Conns</th>
            <th>Active / inactive</th><th>Weight</th><th></th>
          </tr></thead>
          <tbody>
            <tr v-for="b in detailBackends" :key="b.server_id">
              <td>
                <span class="badge" :class="liveBadge(b.live).cls">{{ liveBadge(b.live).text }}</span>
                <span v-if="!b.enabled" class="badge offline" style="margin-left:4px">excluded</span>
              </td>
              <td>
                <strong>{{ b.server_name }}</strong>
                <div class="muted mono">{{ addrKey(b.address, b.port) }}</div>
              </td>
              <td>
                <div class="share-cell">
                  <div class="share-bar" :class="liveBadge(b.live).cls"><span :style="{ width: (b.share == null ? 0 : Math.max(0, Math.min(100, b.share))).toFixed(1) + '%' }"></span></div>
                  <span class="pct">{{ b.share == null ? '—' : b.share.toFixed(0) + '%' }}</span>
                </div>
              </td>
              <td>{{ b.live && b.live.qps != null ? fixed(b.live.qps) : '—' }}</td>
              <td>{{ num(b.live?.queries) }}</td>
              <td>{{ num(b.live?.conns) }}</td>
              <td>{{ b.live && (b.live.active_conns != null || b.live.inactive_conns != null) ? num(b.live.active_conns) + ' / ' + num(b.live.inactive_conns) : '—' }}</td>
              <td>{{ b.live?.weight ?? b.weight }}<span v-if="b.live?.weight != null && b.live.weight !== b.weight" class="muted" :title="'configured weight ' + b.weight"> ({{ b.weight }})</span></td>
              <td class="row-actions" v-if="auth.isEditor">
                <button v-if="b.live?.drained" class="btn btn-sm" @click="drain(selected, b, true)">Undrain</button>
                <button v-else class="btn btn-sm" :disabled="!b.live" @click="drain(selected, b)">Drain</button>
                <button class="btn btn-sm" @click="openBackend(selected, b)">Edit</button>
              </td>
              <td v-else></td>
            </tr>
            <tr v-if="!detailBackends.length"><td colspan="9" class="empty">No backends: add AdGuard servers to this zone.</td></tr>
          </tbody>
        </table>
        <table v-else>
          <thead><tr>
            <th>State</th><th>Backend</th><th>Share</th><th>QPS</th><th>Queries</th><th>Latency</th>
            <th>Outstanding</th><th>Drop rate</th><th>Weight</th><th>Order</th><th></th>
          </tr></thead>
          <tbody>
            <tr v-for="b in detailBackends" :key="b.server_id">
              <td>
                <span class="badge" :class="liveBadge(b.live).cls">{{ liveBadge(b.live).text }}</span>
                <span v-if="!b.enabled" class="badge offline" style="margin-left:4px">excluded</span>
              </td>
              <td>
                <strong>{{ b.server_name }}</strong>
                <div class="muted mono">{{ addrKey(b.address, b.port) }}</div>
                <div v-if="b.live?.health_failures" class="hint" style="color:var(--amber)">{{ b.live.health_failures }} health check failure(s)</div>
              </td>
              <td>
                <div class="share-cell">
                  <div class="share-bar" :class="liveBadge(b.live).cls"><span :style="{ width: Math.max(0, Math.min(100, b.share)).toFixed(1) + '%' }"></span></div>
                  <span class="pct">{{ b.live ? b.share.toFixed(0) + '%' : '—' }}</span>
                </div>
              </td>
              <td>{{ b.live ? fixed(b.live.qps) : '—' }}</td>
              <td>{{ b.live ? num(b.live.queries) : '—' }}</td>
              <td>{{ b.live && b.live.latency_ms != null ? fixed(b.live.latency_ms) + ' ms' : '—' }}</td>
              <td>{{ b.live ? num(b.live.outstanding) : '—' }}</td>
              <td>{{ b.live && b.live.drop_rate != null ? fixed(b.live.drop_rate, 2) : '—' }}</td>
              <td>{{ b.weight }}</td>
              <td>{{ b.order }}</td>
              <td class="row-actions" v-if="auth.isEditor">
                <button v-if="b.live?.drained" class="btn btn-sm" @click="drain(selected, b, true)">Undrain</button>
                <button v-else class="btn btn-sm" :disabled="!b.live" @click="drain(selected, b)">Drain</button>
                <button class="btn btn-sm" @click="openBackend(selected, b)">Edit</button>
              </td>
              <td v-else></td>
            </tr>
            <tr v-if="!detailBackends.length"><td colspan="11" class="empty">No backends: add AdGuard servers to this zone.</td></tr>
          </tbody>
        </table>
        <div v-if="isIpvs(selected)" class="hint" style="padding:10px 16px">
          Share is each backend's part of the packets the kernel has forwarded since the virtual server was programmed.
          Replies go straight from the backend to the client, so there are no out-direction counters.
          <strong>Drain</strong> sets the backend's IPVS weight to 0; a keepalived check transition can restore it, and the agent re-applies the drain every 30 s.
        </div>
        <div v-else class="hint" style="padding:10px 16px">
          Share is each backend's part of all queries this balancer has forwarded since dnsdist started.
          <strong>Drain</strong> marks a backend down in dnsdist without removing it, so you can work on a server; it stays drained until undrained.
        </div>
      </div>

      <div class="stats-grid" style="margin-top:24px;align-items:start">
        <div v-if="isIpvs(selected)" class="card">
          <div class="card-header"><h2>IPVS</h2>
            <span v-if="detailKeepalived" class="badge" :class="detailKeepalived.state === 'ready' ? 'synced' : detailKeepalived.state === 'error' ? 'error' : 'drift'">{{ detailKeepalived.state }}</span>
          </div>
          <div v-if="detailKeepalived?.message" class="alert alert-error" style="margin:12px 16px 0">{{ detailKeepalived.message }}</div>
          <div class="kv-grid">
            <div><div class="k">Virtual servers</div><div class="v">{{ detailIpvs ? (detailIpvs.present === false ? 'none' : num(detailIpvs.services)) : '—' }}</div></div>
            <div><div class="k">VIP owner</div><div class="v">
              <span v-if="detailKeepalived?.vip_owner" class="badge synced">this host</span>
              <span v-else-if="detailKeepalived" class="badge offline">standby</span>
              <span v-else class="muted">no data</span>
            </div></div>
            <div><div class="k">Interface</div><div class="v mono" style="font-weight:500">{{ detailKeepalived?.interface || selected.vip_interface || 'auto' }}</div></div>
            <div><div class="k">Scheduler</div><div class="v">{{ ALGOS.find((a) => a.value === selected.ipvs_algo)?.label.split(' (')[0] || selected.ipvs_algo }}</div></div>
            <div><div class="k">Backends up</div><div class="v">{{ upCount(selected) }} of {{ backendsOf(selected).length }}</div></div>
            <div><div class="k">keepalived</div><div class="v mono" style="font-weight:500">{{ detailKeepalived?.version || '—' }}</div></div>
          </div>
          <div v-if="ipvsDiag" class="diag-list">
            <div v-for="item in DIAG_ITEMS" :key="item.key" class="diag-item" :class="ipvsDiag[item.key] ? 'ok' : 'bad'">
              <span class="diag-mark">{{ ipvsDiag[item.key] ? '✓' : '✗' }}</span>{{ item.label }}
            </div>
            <div v-if="ipvsDiag.container" class="diag-item info">
              <span class="diag-mark">i</span>runs inside a {{ ipvsDiag.container }} container (kernel modules come from the node)
            </div>
            <div v-if="ipvsDiag.modprobe_error" class="hint" style="color:var(--red);margin-top:4px">modprobe: {{ ipvsDiag.modprobe_error }}</div>
            <div v-if="ipvsDiag.checked_at" class="muted" style="font-size:11px;margin-top:4px">checked {{ fmt(ipvsDiag.checked_at) }}</div>
          </div>
          <div class="hint" style="padding:0 16px 14px">
            Direct routing: the VIP owner rewrites the destination MAC and the backend answers the client itself,
            so AdGuard sees the real client address. Every backend carries the VIP on loopback; the agent sets that up on managed hosts.
          </div>
        </div>
        <div v-else class="card">
          <div class="card-header"><h2>dnsdist</h2>
            <span v-if="detailDnsdist" class="badge" :class="detailDnsdist.state === 'ready' ? 'synced' : detailDnsdist.state === 'error' ? 'error' : 'drift'">{{ detailDnsdist.state }}</span>
          </div>
          <div v-if="detailDnsdist?.message" class="alert alert-error" style="margin:12px 16px 0">{{ detailDnsdist.message }}</div>
          <div v-if="detailStats" class="kv-grid">
            <div><div class="k">Queries</div><div class="v">{{ num(detailStats.queries) }}</div></div>
            <div><div class="k">Responses</div><div class="v">{{ num(detailStats.responses) }}</div></div>
            <div><div class="k">SERVFAIL</div><div class="v" :style="Number(detailStats['servfail-responses']) ? 'color:var(--red)' : ''">{{ num(detailStats['servfail-responses']) }}</div></div>
            <div><div class="k">Downstream timeouts</div><div class="v" :style="Number(detailStats['downstream-timeouts']) ? 'color:var(--amber)' : ''">{{ num(detailStats['downstream-timeouts']) }}</div></div>
            <div><div class="k">Send errors</div><div class="v">{{ num(detailStats['downstream-send-errors']) }}</div></div>
            <div><div class="k">Latency (last 100)</div><div class="v">{{ detailStats['latency-avg100'] != null ? fixed(Number(detailStats['latency-avg100']) / 1000, 2) + ' ms' : '—' }}</div></div>
            <div><div class="k">Latency (last 10k)</div><div class="v">{{ detailStats['latency-avg10000'] != null ? fixed(Number(detailStats['latency-avg10000']) / 1000, 2) + ' ms' : '—' }}</div></div>
            <div v-if="selected.cache_enabled"><div class="k">Cache hit rate</div><div class="v">{{ cacheHitRate == null ? '—' : cacheHitRate + '%' }}</div></div>
            <div><div class="k">Non-compliant</div><div class="v">{{ num(detailStats['noncompliant-queries']) }}</div></div>
            <div><div class="k">Memory</div><div class="v">{{ detailStats['real-memory-usage'] != null ? (Number(detailStats['real-memory-usage']) / 1048576).toFixed(0) + ' MB' : '—' }}</div></div>
            <div><div class="k">Uptime</div><div class="v">{{ uptime(detailStats.uptime) }}</div></div>
            <div><div class="k">Version</div><div class="v mono" style="font-weight:500">{{ detailDnsdist?.version || '—' }}</div></div>
          </div>
          <div v-else class="empty" style="padding:24px">No statistics yet — the host has not reported.</div>
          <table v-if="!isIpvs(selected) && detailFrontends.length">
            <thead><tr><th>Frontend</th><th>Protocol</th><th>Queries</th><th>Responses</th></tr></thead>
            <tbody>
              <tr v-for="(f, i) in detailFrontends" :key="i">
                <td class="mono">{{ f.address }}</td>
                <td>{{ (f.protocol || '').toUpperCase() }}</td>
                <td>{{ num(f.queries) }}</td>
                <td>{{ num(f.responses) }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-header"><h2>Virtual IP</h2>
            <span v-if="detailKeepalived" class="badge" :class="detailKeepalived.state === 'ready' ? 'synced' : detailKeepalived.state === 'error' ? 'error' : 'drift'">{{ detailKeepalived.state }}</span>
          </div>
          <div v-if="zoneOf(selected)?.vip" class="kv-grid">
            <div><div class="k">Address</div><div class="v mono" style="font-weight:500">{{ zoneOf(selected).vip }}</div></div>
            <div><div class="k">This host</div><div class="v">
              <span v-if="detailKeepalived?.vip_owner" class="badge synced">owner</span>
              <span v-else-if="detailKeepalived" class="badge offline">standby</span>
              <span v-else class="muted">no data</span>
            </div></div>
            <div><div class="k">Current owner</div><div class="v">{{ ownerOf(zoneOf(selected)) || '—' }}</div></div>
            <div><div class="k">Priority</div><div class="v">{{ selected.vrrp_priority }}</div></div>
            <div><div class="k">Interface</div><div class="v mono" style="font-weight:500">{{ detailKeepalived?.interface || selected.vip_interface || 'auto' }}</div></div>
            <div><div class="k">keepalived</div><div class="v mono" style="font-weight:500">{{ detailKeepalived?.version || '—' }}</div></div>
          </div>
          <div v-else class="empty" style="padding:24px">
            This zone has no VIP. Set one under <router-link to="/zones">Zones</router-link> and clients can use a single address that fails over between balancers.
          </div>
          <div v-if="detailKeepalived?.message" class="alert alert-error" style="margin:0 16px 16px">{{ detailKeepalived.message }}</div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Configuration</h2></div>
          <div v-if="isIpvs(selected)" class="kv-grid">
            <div><div class="k">Mode</div><div class="v">IPVS direct routing</div></div>
            <div><div class="k">Service</div><div class="v mono" style="font-weight:500">{{ zoneOf(selected)?.vip ? zoneOf(selected).vip.split('/')[0] + ':53 udp+tcp' : 'no VIP on the zone' }}</div></div>
            <div><div class="k">Scheduler</div><div class="v">{{ ALGOS.find((a) => a.value === selected.ipvs_algo)?.label.split(' (')[0] || selected.ipvs_algo }}</div></div>
            <div><div class="k">Health check</div><div class="v" style="font-weight:500">DNS probe every {{ selected.hc_interval_s }}s · down after {{ selected.hc_max_failures }} retries</div></div>
            <div><div class="k">Config hash</div><div class="v mono" style="font-weight:500;font-size:12px">{{ (selected.applied_hash || '').slice(0, 12) || '—' }}<span v-if="selected.desired_hash && selected.desired_hash !== selected.applied_hash" class="badge drift" style="margin-left:6px">pending</span></div></div>
          </div>
          <div v-else class="kv-grid">
            <div><div class="k">Mode</div><div class="v">dnsdist proxy</div></div>
            <div><div class="k">Listen</div><div class="v mono" style="font-weight:500">{{ (selected.listen_addresses || []).join(', ') || '—' }}</div></div>
            <div><div class="k">Policy</div><div class="v">{{ POLICIES.find((p) => p.value === selected.policy)?.label.split(' (')[0] || selected.policy }}</div></div>
            <div><div class="k">Health check</div><div class="v" style="font-weight:500">{{ selected.hc_name }} every {{ selected.hc_interval_s }}s · down after {{ selected.hc_max_failures }}, up after {{ selected.hc_rise }}</div></div>
            <div><div class="k">EDNS client subnet</div><div class="v">{{ selected.ecs ? 'on' : 'off' }}</div></div>
            <div><div class="k">Cache</div><div class="v">{{ selected.cache_enabled ? num(selected.cache_max_entries) + ' entries' : 'off' }}</div></div>
            <div><div class="k">ACL</div><div class="v mono" style="font-weight:500;font-size:12px">{{ (selected.acl || []).join(', ') || 'none' }}</div></div>
            <div><div class="k">Install</div><div class="v">{{ selected.install_method }}<span v-if="selected.image" class="muted mono" style="font-size:12px"> · {{ selected.image }}</span></div></div>
            <div><div class="k">Config hash</div><div class="v mono" style="font-weight:500;font-size:12px">{{ (selected.applied_hash || '').slice(0, 12) || '—' }}<span v-if="selected.desired_hash && selected.desired_hash !== selected.applied_hash" class="badge drift" style="margin-left:6px">pending</span></div></div>
          </div>
        </div>
      </div>
    </template>
  </div>

  <!-- Create / edit -->
  <Modal v-if="showModal" :title="editing ? 'Edit load balancer' : 'Add load balancer'" @close="showModal = false">
    <div v-if="formError" class="alert alert-error">{{ formError }}</div>
    <div class="form-row">
      <label>Name</label>
      <input v-model="form.name" placeholder="lb-home-a" />
    </div>
    <div class="form-grid">
      <div class="form-row">
        <label>Zone</label>
        <select v-model="form.zone_id">
          <option :value="null">— choose a zone —</option>
          <option v-for="z in zones" :key="z.id" :value="z.id">{{ z.name }}<template v-if="z.vip"> · VIP {{ z.vip }}</template></option>
        </select>
      </div>
      <div class="form-row">
        <label>Host</label>
        <select v-model="form.agent_id" :disabled="!!editing">
          <option :value="null">— choose a host —</option>
          <option v-for="a in agentChoices" :key="a.id" :value="a.id">{{ a.name }} ({{ a.address }})<template v-if="a.zone_id !== form.zone_id"> · {{ zoneName(a.zone_id) }}</template></option>
        </select>
      </div>
    </div>
    <div class="form-row" style="margin-top:12px">
      <label>Mode</label>
      <select v-model="form.mode" :disabled="!!editing">
        <option v-for="m in MODES" :key="m.value" :value="m.value">{{ m.label }} — {{ m.hint }}</option>
      </select>
      <div class="hint">
        <template v-if="formIpvs">
          keepalived programs the kernel's IPVS table on the VIP owner and routes each query to a backend by MAC; the backend replies to the client directly, so AdGuard logs the real client.
          All balancers in a zone must use the same mode. Every AdGuard in the zone listens on port 53 on its own address.
        </template>
        <template v-else>
          The balancer forwards to every enabled AdGuard server in the zone. A host that also runs AdGuard keeps it as a backend on loopback.
        </template>
      </div>
      <div v-if="formMissingVip" class="alert alert-error" style="margin-top:10px">IPVS mode needs a VIP on the zone. Set one under <router-link to="/zones">Zones</router-link> first.</div>
    </div>
    <div class="form-row checkbox-row" style="margin-top:12px">
      <input type="checkbox" id="lb-enabled" v-model="form.enabled" />
      <label for="lb-enabled" style="margin:0">Enabled (reconciled and running)</label>
    </div>

    <template v-if="formIpvs">
      <h3 style="font-size:14px;margin:18px 0 10px">Scheduling and health check</h3>
      <div class="form-row">
        <label>Scheduler</label>
        <select v-model="form.ipvs_algo">
          <option v-for="a in ALGOS" :key="a.value" :value="a.value">{{ a.label }}</option>
        </select>
        <div class="hint">Source hash keeps a client on one backend, which keeps AdGuard's per-client statistics on a single server.</div>
      </div>
      <div class="form-grid">
        <div class="form-row">
          <label>Check interval (s)</label>
          <input v-model.number="form.hc_interval_s" type="number" min="1" />
        </div>
        <div class="form-row">
          <label>Retries before down</label>
          <input v-model.number="form.hc_max_failures" type="number" min="1" />
        </div>
      </div>
      <div class="hint">keepalived sends a DNS query to each backend on its own address; a failing backend stays in the table at weight 0 so it shows as down.</div>
    </template>

    <h3 v-if="!formIpvs" style="font-size:14px;margin:18px 0 10px">Listeners and policy</h3>
    <div v-if="!formIpvs" class="form-grid">
      <div class="form-row">
        <label>Listen addresses</label>
        <textarea v-model="form.listen_text" rows="2" placeholder="0.0.0.0:53"></textarea>
        <div class="hint">One per line. The VIP is covered by 0.0.0.0.</div>
      </div>
      <div class="form-row">
        <label>Policy</label>
        <select v-model="form.policy">
          <option v-for="p in POLICIES" :key="p.value" :value="p.value">{{ p.label }}</option>
        </select>
      </div>
    </div>
    <div v-if="!formIpvs" class="form-row checkbox-row">
      <input type="checkbox" id="lb-ecs" v-model="form.ecs" />
      <label for="lb-ecs" style="margin:0">Add the client's subnet (EDNS Client Subnet) to forwarded queries</label>
    </div>
    <div v-if="!formIpvs" class="hint">AdGuard Home shows the subnet in query-log details, but it identifies clients by source address, which behind a balancer is the balancer's own. Per-client rules in AdGuard do not apply to balanced traffic.</div>

    <h3 v-if="!formIpvs" style="font-size:14px;margin:18px 0 10px">Health check</h3>
    <div v-if="!formIpvs" class="form-grid">
      <div class="form-row">
        <label>Query name</label>
        <input v-model="form.hc_name" placeholder="a.root-servers.net." />
      </div>
      <div class="form-row">
        <label>Mode</label>
        <select v-model="form.hc_mode">
          <option value="auto">Active (probe every interval)</option>
          <option value="lazy">Lazy (probe only after failures)</option>
        </select>
      </div>
      <div class="form-row">
        <label>Interval (s)</label>
        <input v-model.number="form.hc_interval_s" type="number" min="1" />
      </div>
      <div class="form-row">
        <label>Failures before down</label>
        <input v-model.number="form.hc_max_failures" type="number" min="1" />
      </div>
      <div class="form-row">
        <label>Successes before up</label>
        <input v-model.number="form.hc_rise" type="number" min="1" />
      </div>
    </div>

    <h3 v-if="!formIpvs" style="font-size:14px;margin:18px 0 10px">Cache</h3>
    <div v-if="!formIpvs" class="form-row checkbox-row">
      <input type="checkbox" id="lb-cache" v-model="form.cache_enabled" />
      <label for="lb-cache" style="margin:0">Cache answers in dnsdist</label>
    </div>
    <div class="form-row" v-if="!formIpvs && form.cache_enabled">
      <label>Max entries</label>
      <input v-model.number="form.cache_max_entries" type="number" min="1000" />
    </div>
    <div v-if="!formIpvs" class="hint">Off by default: AdGuard already caches, and a cache in front of it undercounts AdGuard's statistics and can serve an answer after a blocking rule changed.</div>

    <h3 style="font-size:14px;margin:18px 0 10px">{{ formIpvs ? 'VRRP' : 'Access and VRRP' }}</h3>
    <div v-if="!formIpvs" class="form-row">
      <label>Allowed client networks (ACL)</label>
      <textarea v-model="form.acl_text" rows="3"></textarea>
      <div class="hint">CIDRs, one per line. Queries from anywhere else are dropped.</div>
    </div>
    <div class="form-grid">
      <div class="form-row">
        <label>VRRP priority</label>
        <input v-model.number="form.vrrp_priority" type="number" min="1" max="254" :disabled="!formZone?.vip" />
        <div class="hint">{{ formZone?.vip ? 'Highest priority holds the VIP ' + formZone.vip + '.' : 'The zone has no VIP.' }}</div>
      </div>
      <div class="form-row">
        <label>VIP interface</label>
        <input v-model="form.vip_interface" placeholder="auto" :disabled="!formZone?.vip" />
      </div>
    </div>
    <div v-if="!formIpvs" class="form-grid">
      <div class="form-row">
        <label>Install method</label>
        <select v-model="form.install_method">
          <option value="docker">Docker container</option>
          <option value="bare_metal">Distro package</option>
        </select>
      </div>
      <div class="form-row">
        <label>Image</label>
        <input v-model="form.image" :disabled="form.install_method !== 'docker'" placeholder="powerdns/dnsdist-20:2.0.8" />
      </div>
    </div>
    <template #footer>
      <button class="btn" @click="showModal = false">Cancel</button>
      <button class="btn btn-primary" :disabled="saving || !form.name || !form.zone_id || !form.agent_id || formMissingVip" @click="save">
        <span v-if="saving" class="spinner"></span><span>Save</span>
      </button>
    </template>
  </Modal>

  <!-- Backend override -->
  <Modal v-if="backendTarget" :title="`Backend — ${backendTarget.backend.server_name}`" @close="backendTarget = null">
    <div v-if="backendError" class="alert alert-error">{{ backendError }}</div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="be-enabled" v-model="backendForm.enabled" />
      <label for="be-enabled" style="margin:0">Include this server as a backend</label>
    </div>
    <div class="form-grid">
      <div class="form-row">
        <label>Weight</label>
        <input v-model.number="backendForm.weight" type="number" min="1" />
        <div class="hint">Used by weighted policies. Higher gets more queries.</div>
      </div>
      <div class="form-row">
        <label>Order</label>
        <input v-model.number="backendForm.order" type="number" min="1" />
        <div class="hint">Lower is preferred by least-outstanding and first-available.</div>
      </div>
    </div>
    <template #footer>
      <button class="btn" @click="backendTarget = null">Cancel</button>
      <button class="btn btn-primary" @click="saveBackend">Save</button>
    </template>
  </Modal>

  <Modal v-if="logsTarget" :title="`${logsService} logs — ${agentName(logsTarget.agent_id)}`" @close="logsTarget = null">
    <div class="flex" style="gap:10px;margin-bottom:12px">
      <select v-model="logsService" style="width:auto" @change="fetchLogs">
        <option v-if="!isIpvs(logsTarget)" value="dnsdist">dnsdist</option>
        <option value="keepalived">keepalived</option>
        <option value="agent">agent</option>
      </select>
      <button class="btn btn-sm" :disabled="logsLoading" @click="fetchLogs">{{ logsLoading ? 'Loading…' : 'Reload' }}</button>
    </div>
    <div v-if="logsError" class="alert alert-error">{{ logsError }}</div>
    <pre v-else-if="logs" class="log-box mono">{{ logs.length ? logs.join('\n') : '(no output)' }}</pre>
    <div v-else class="muted">Loading…</div>
    <template #footer><button class="btn btn-primary" @click="logsTarget = null">Close</button></template>
  </Modal>
</template>
