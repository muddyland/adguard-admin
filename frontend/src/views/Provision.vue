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

async function load() {
  const [t, z] = await Promise.all([api.get('/provision/tokens'), api.get('/zones')])
  tokens.value = t.data
  zones.value = z.data
}

function openForm() {
  form.value = { name: '', zone_id: null, method: 'docker', ssl_enabled: false,
                 connect_address: '', http_port: null, https_port: null, prune: false }
  error.value = ''
  result.value = null
  showForm.value = true
}

async function create() {
  error.value = ''
  const payload = { ...form.value }
  if (!payload.http_port) delete payload.http_port
  if (!payload.https_port) delete payload.https_port
  if (!payload.ssl_enabled) delete payload.connect_address
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
    <button class="btn btn-primary" @click="openForm">+ Provision new server</button>
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
        <thead><tr><th>Name</th><th>Zone</th><th>Method</th><th>SSL</th><th>Status</th><th>Expires</th><th></th></tr></thead>
        <tbody>
          <tr v-for="t in visibleTokens" :key="t.id">
            <td><strong>{{ t.name }}</strong></td>
            <td>{{ zoneName(t.zone_id) }}</td>
            <td><span class="badge global">{{ t.method === 'docker' ? 'Docker' : 'Bare-metal' }}</span></td>
            <td>{{ t.ssl_enabled ? '🔒 ' + t.connect_address : '—' }}</td>
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
              <span v-if="t.status === 'completed'" class="muted" style="margin-right:6px">server #{{ t.server_id }}</span>
              <button class="btn btn-sm btn-danger" @click="remove(t)">Delete</button>
            </td>
          </tr>
          <tr v-if="!visibleTokens.length"><td colspan="7" class="empty">No provisioning requests to show.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Request form / result -->
  <Modal v-if="showForm" :title="result ? 'Run this on the new server' : 'Provision a new server'" @close="showForm = false">
    <template v-if="!result">
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div class="form-row">
        <label>Server name</label>
        <input v-model="form.name" placeholder="cloud-adguard-1" />
      </div>
      <div class="form-row">
        <label>Zone</label>
        <select v-model="form.zone_id">
          <option :value="null">— Unzoned (global records only) —</option>
          <option v-for="z in zones" :key="z.id" :value="z.id">{{ z.name }}</option>
        </select>
      </div>
      <div class="form-row">
        <label>Install method</label>
        <select v-model="form.method">
          <option value="docker">Docker (recommended)</option>
          <option value="bare_metal">Bare-metal (systemd service)</option>
        </select>
      </div>
      <div class="form-row checkbox-row">
        <input type="checkbox" id="ssl" v-model="form.ssl_enabled" />
        <label for="ssl" style="margin:0">Enable SSL/TLS (cert is provisioned for you)</label>
      </div>
      <div class="form-row" v-if="form.ssl_enabled">
        <label>Address (FQDN or IP the admin app will use)</label>
        <input v-model="form.connect_address" placeholder="adguard1.example.com" />
        <div class="hint">A self-signed cert is generated for this address and pinned by the admin app.</div>
      </div>
      <div class="form-grid">
        <div class="form-row">
          <label>HTTP port</label>
          <input v-model.number="form.http_port" type="number" placeholder="3000" />
        </div>
        <div class="form-row" v-if="form.ssl_enabled">
          <label>HTTPS port</label>
          <input v-model.number="form.https_port" type="number" placeholder="443" />
        </div>
      </div>
      <div class="form-row checkbox-row">
        <input type="checkbox" id="prune" v-model="form.prune" />
        <label for="prune" style="margin:0">Prune un-managed rewrites once managed</label>
      </div>
    </template>

    <template v-else>
      <p>Copy this one-line command and run it as root on the new server. It installs
         AdGuard Home, applies your settings{{ result.ssl_enabled ? ' and the TLS certificate' : '' }},
         then registers the server here automatically.</p>
      <div style="position:relative">
        <pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;overflow-x:auto;font-size:13px;white-space:pre-wrap;word-break:break-all">{{ result.command }}</pre>
      </div>
      <button class="btn btn-primary btn-sm" style="margin-top:10px" @click="copy(result.command, 'result')">
        {{ copied === 'result' ? 'Copied!' : 'Copy command' }}
      </button>
      <div class="hint" style="margin-top:14px">
        Token expires {{ fmt(result.expires_at) }}. The server appears in the list below as
        <strong>pending</strong> until the script finishes, then flips to <strong>completed</strong>.
      </div>
    </template>

    <template #footer>
      <template v-if="!result">
        <button class="btn" @click="showForm = false">Cancel</button>
        <button class="btn btn-primary" @click="create">Generate command</button>
      </template>
      <button v-else class="btn btn-primary" @click="showForm = false">Done</button>
    </template>
  </Modal>
</template>
