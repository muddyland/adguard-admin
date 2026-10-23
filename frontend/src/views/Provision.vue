<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'

const auth = useAuth()
const tokens = ref([])
const zones = ref([])
const showRevoked = ref(true)

const visibleTokens = computed(() =>
  showRevoked.value ? tokens.value : tokens.value.filter((t) => t.status !== 'revoked')
)
const showForm = ref(false)
const result = ref(null)         // the created token (shows the command)
const error = ref('')
const copied = ref('')
const form = ref({})

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || 'Unzoned'
const formZone = computed(() => zones.value.find((z) => z.id === form.value.zone_id))
const rolesOf = (t) => (Array.isArray(t.roles) && t.roles.length ? t.roles : ['adguard'])
// IPVS direct routing has no address of its own: the zone VIP is the service.
const ipvsMissingVip = computed(() => form.value.role_dnsdist && form.value.lb_mode === 'ipvs' && !formZone.value?.vip)

async function load() {
  const [t, z] = await Promise.all([api.get('/provision/tokens'), api.get('/zones')])
  tokens.value = t.data
  zones.value = z.data
}

function openForm() {
  form.value = { name: '', zone_id: null, role_adguard: true, role_dnsdist: false, method: 'docker',
                 connect_address: '', agent_port: 8443, prune: false, auto_update: false,
                 expose_web_ui: false, vrrp_priority: 100, lb_mode: 'dnsdist' }
  error.value = ''
  result.value = null
  showForm.value = true
}

async function create() {
  error.value = ''
  const f = form.value
  const roles = []
  if (f.role_adguard) roles.push('adguard')
  if (f.role_dnsdist) roles.push('dnsdist')
  if (!roles.length) { error.value = 'Pick at least one role for the host.'; return }
  const payload = {
    name: f.name, zone_id: f.zone_id, roles, method: f.method,
    prune: f.prune, auto_update: f.auto_update, expose_web_ui: f.expose_web_ui,
  }
  if (f.connect_address && f.connect_address.trim()) payload.connect_address = f.connect_address.trim()
  if (f.agent_port) payload.agent_port = Number(f.agent_port)
  if (f.role_dnsdist) payload.lb_mode = f.lb_mode || 'dnsdist'
  if (f.role_dnsdist && formZone.value?.vip) payload.vrrp_priority = Number(f.vrrp_priority) || 100
  try {
    const { data } = await api.post('/provision/tokens', payload)
    result.value = data
    await load()
  } catch (e) { error.value = e.response?.data?.detail || 'Failed to create token' }
}

async function copy(text, id) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = id
    setTimeout(() => (copied.value = ''), 1500)
  } catch { /* clipboard blocked */ }
}

async function revoke(t) {
  if (!confirm(`Revoke the token for "${t.name}"? The one-line command will stop working.`)) return
  await api.post(`/provision/tokens/${t.id}/revoke`)
  await load()
}

async function remove(t) {
  if (!confirm(`Delete the provisioning record for "${t.name}"?`)) return
  await api.delete(`/provision/tokens/${t.id}`)
  await load()
}

function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Provisioning</h1>
    <button class="btn btn-primary" @click="openForm">+ Provision new host</button>
  </div>
  <div class="content">
    <div class="card">
      <div class="card-header">
        <h2>Provisioning tokens</h2>
        <label class="checkbox-row" style="font-weight:500">
          <input type="checkbox" v-model="showRevoked" /> Show revoked
        </label>
      </div>
      <table>
        <thead><tr><th>Name</th><th>Zone</th><th>Roles</th><th>Address</th><th>Status</th><th>Expires</th><th></th></tr></thead>
        <tbody>
          <tr v-for="t in visibleTokens" :key="t.id">
            <td><strong>{{ t.name }}</strong></td>
            <td>{{ zoneName(t.zone_id) }}</td>
            <td>
              <div class="badges">
                <span v-for="r in rolesOf(t)" :key="r" class="badge" :class="'role-' + r">{{ r }}</span>
                <span v-if="rolesOf(t).includes('dnsdist') && t.lb_mode" class="badge" :class="'mode-' + t.lb_mode" :title="'Load balancer mode'">{{ t.lb_mode }}</span>
                <span v-if="rolesOf(t).includes('adguard')" class="badge global" :title="'AdGuard install method'">{{ t.method === 'docker' ? 'Docker' : 'Bare-metal' }}</span>
                <span v-if="t.auto_update" class="badge synced" title="Auto-update enabled">auto-update</span>
              </div>
            </td>
            <td class="mono">{{ t.connect_address || 'auto' }}<span class="muted">:{{ t.agent_port || 8443 }}</span></td>
            <td>
              <span v-if="t.status === 'completed'" class="badge synced">completed</span>
              <span v-else-if="t.status === 'pending'" class="badge drift">pending</span>
              <span v-else class="badge offline">revoked</span>
            </td>
            <td class="muted">{{ fmt(t.expires_at) }}</td>
            <td class="row-actions">
              <button v-if="t.status === 'pending'" class="btn btn-sm" @click="copy(t.command, t.id)">
                {{ copied === t.id ? 'Copied!' : 'Copy command' }}
              </button>
              <button v-if="t.status === 'pending'" class="btn btn-sm" @click="revoke(t)">Revoke</button>
              <span v-if="t.status === 'completed'" class="muted" style="margin-right:6px">
                <template v-if="t.agent_id">host #{{ t.agent_id }}</template>
                <template v-if="t.server_id"> · server #{{ t.server_id }}</template>
                <template v-if="t.load_balancer_id"> · balancer #{{ t.load_balancer_id }}</template>
              </span>
              <button class="btn btn-sm btn-danger" @click="remove(t)">Delete</button>
            </td>
          </tr>
          <tr v-if="!visibleTokens.length"><td colspan="7" class="empty">No provisioning requests to show.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Request form / result -->
  <Modal v-if="showForm" :title="result ? 'Run this on the new host' : 'Provision a new host'" @close="showForm = false">
    <template v-if="!result">
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div class="form-row">
        <label>Host name</label>
        <input v-model="form.name" placeholder="dns-a" />
      </div>
      <div class="form-row">
        <label>Zone</label>
        <select v-model="form.zone_id">
          <option :value="null">— Unzoned (global records only) —</option>
          <option v-for="z in zones" :key="z.id" :value="z.id">{{ z.name }}</option>
        </select>
      </div>
      <div class="form-row">
        <label>Roles on this host</label>
        <div class="checkbox-row" style="margin-top:4px">
          <input type="checkbox" id="role-adguard" v-model="form.role_adguard" />
          <label for="role-adguard" style="margin:0">AdGuard Home (resolver)</label>
        </div>
        <div class="checkbox-row" style="margin-top:6px">
          <input type="checkbox" id="role-dnsdist" v-model="form.role_dnsdist" />
          <label for="role-dnsdist" style="margin:0">Load balancer</label>
        </div>
        <div class="hint">
          A host can run both. Run both roles on each zone server and give the zone a VIP for redundancy.
        </div>
      </div>
      <div class="form-row" v-if="form.role_dnsdist">
        <label>Load balancer mode</label>
        <select v-model="form.lb_mode">
          <option value="dnsdist">dnsdist proxy — per-query stats, works across VLANs; backends see the balancer's address</option>
          <option value="ipvs">IPVS direct routing — kernel L4, backends see the real client; needs a zone VIP and one L2 segment</option>
        </select>
        <div class="hint">
          <template v-if="form.lb_mode === 'ipvs'">
            keepalived owns the VIP and programs the kernel's IPVS table; every AdGuard in the zone listens on port 53 on its own
            address and replies to clients directly. All balancers in a zone must share one mode.
          </template>
          <template v-else>
            dnsdist takes port 53 on this host and forwards to every AdGuard server in the zone, including the one on loopback.
          </template>
        </div>
        <div v-if="ipvsMissingVip" class="alert alert-error" style="margin-top:10px">
          IPVS mode needs a VIP on the zone. Set one under <router-link to="/zones">Zones</router-link> first.
        </div>
      </div>
      <div class="form-row" v-if="form.role_adguard">
        <label>AdGuard install method</label>
        <select v-model="form.method">
          <option value="docker">Docker (recommended)</option>
          <option value="bare_metal">Bare-metal (native install)</option>
        </select>
      </div>
      <div class="form-grid">
        <div class="form-row">
          <label>Connect address (optional)</label>
          <input v-model="form.connect_address" placeholder="auto-detected on the box" />
          <div class="hint">FQDN or IP the admin app will use to reach the agent; goes into its certificate.</div>
        </div>
        <div class="form-row">
          <label>Agent port</label>
          <input v-model.number="form.agent_port" type="number" min="1" max="65535" placeholder="8443" />
        </div>
      </div>
      <div class="form-row" v-if="form.role_dnsdist && formZone?.vip">
        <label>VRRP priority for {{ formZone.vip }}</label>
        <input v-model.number="form.vrrp_priority" type="number" min="1" max="254" placeholder="100" />
        <div class="hint">The balancer with the highest priority holds the zone's VIP; the others stand by.</div>
      </div>
      <div class="hint" v-else-if="form.role_dnsdist && form.zone_id && !formZone?.vip" style="margin-bottom:12px">
        This zone has no VIP yet. Add one under <router-link to="/zones">Zones</router-link> so clients can use a single address.
      </div>
      <template v-if="form.role_adguard">
        <div class="form-row checkbox-row">
          <input type="checkbox" id="prune" v-model="form.prune" />
          <label for="prune" style="margin:0">Prune un-managed rewrites once managed</label>
        </div>
        <div class="form-row checkbox-row">
          <input type="checkbox" id="auto-update" v-model="form.auto_update" />
          <label for="auto-update" style="margin:0">Keep AdGuard Home up to date automatically</label>
        </div>
        <div class="form-row checkbox-row">
          <input type="checkbox" id="expose-ui" v-model="form.expose_web_ui" />
          <label for="expose-ui" style="margin:0">Expose AdGuard's web UI on the LAN</label>
        </div>
        <div class="hint">
          Off keeps AdGuard's own admin UI on loopback; the agent still lets you open it from here over mutual TLS.
          Upgrades are driven through the agent, whatever the install method.
        </div>
      </template>
    </template>

    <template v-else>
      <p>Copy this one-line command and run it as root on the new host. It installs the
         <strong>AdGuard Admin agent</strong>, which enrolls here over mutual TLS. From then on the
         control plane converges the host's roles
         ({{ rolesOf(result).join(' + ') }}): installing and configuring the software and keeping it in sync.</p>
      <div style="position:relative">
        <pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;overflow-x:auto;font-size:13px;white-space:pre-wrap;word-break:break-all">{{ result.command }}</pre>
      </div>
      <button class="btn btn-primary btn-sm" style="margin-top:10px" @click="copy(result.command, 'result')">
        {{ copied === 'result' ? 'Copied!' : 'Copy command' }}
      </button>
      <div class="hint" style="margin-top:14px">
        Token expires {{ fmt(result.expires_at) }}. The request shows as <strong>pending</strong> until the
        agent enrolls, then <strong>completed</strong>; the host appears under <router-link to="/hosts">Hosts</router-link>
        and its roles converge over the next sync passes.
      </div>
    </template>

    <template #footer>
      <template v-if="!result">
        <button class="btn" @click="showForm = false">Cancel</button>
        <button class="btn btn-primary" :disabled="ipvsMissingVip" @click="create">Generate command</button>
      </template>
      <button v-else class="btn btn-primary" @click="showForm = false">Done</button>
    </template>
  </Modal>
</template>
