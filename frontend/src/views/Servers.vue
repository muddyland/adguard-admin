<script setup>
import { ref, onMounted, computed } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'

const auth = useAuth()
const servers = ref([])
const zones = ref([])
const showModal = ref(false)
const editing = ref(null)
const form = ref({})
const error = ref('')
const testResult = ref({})
const syncingId = ref(null)
const msg = ref('')
// Standalone "import from existing server" modal
const importTarget = ref(null)
const importScope = ref('global')
const importing = ref(false)

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || 'Unzoned'

async function load() {
  const [s, z] = await Promise.all([api.get('/servers'), api.get('/zones')])
  servers.value = s.data
  zones.value = z.data
}

function openCreate() {
  editing.value = null
  form.value = { name: '', url: '', username: '', password: '', zone_id: null, enabled: true, prune: false,
                 import_records: false, import_scope: 'global' }
  error.value = ''
  showModal.value = true
}
function openEdit(s) {
  editing.value = s
  form.value = { name: s.name, url: s.url, username: s.username || '', password: '', zone_id: s.zone_id, enabled: s.enabled, prune: s.prune }
  error.value = ''
  showModal.value = true
}

async function save() {
  error.value = ''
  const payload = { ...form.value }
  const wantImport = !editing.value && payload.import_records
  const importScopeChoice = payload.import_scope
  delete payload.import_records
  delete payload.import_scope
  if (editing.value && !payload.password) delete payload.password // keep existing
  try {
    let created = null
    if (editing.value) {
      await api.patch(`/servers/${editing.value.id}`, payload)
    } else {
      created = (await api.post('/servers', payload)).data
    }
    showModal.value = false
    if (created && wantImport) {
      try {
        const { data } = await api.post(`/servers/${created.id}/import`, null, { params: { scope: importScopeChoice } })
        msg.value = `Imported ${data.imported} record(s) from ${created.name}; ${data.skipped} already existed.`
      } catch (e) {
        msg.value = `Server added, but import failed: ${e.response?.data?.detail || 'unknown error'}`
      }
    }
    await load()
  } catch (e) { error.value = e.response?.data?.detail || 'Save failed' }
}

function openImport(s) {
  importTarget.value = s
  importScope.value = s.zone_id ? 'zone' : 'global'
}

async function runImport() {
  importing.value = true
  try {
    const { data } = await api.post(`/servers/${importTarget.value.id}/import`, null, { params: { scope: importScope.value } })
    msg.value = `Imported ${data.imported} record(s) from ${importTarget.value.name}; ${data.skipped} already existed.`
    importTarget.value = null
    await load()
  } catch (e) {
    msg.value = `Import failed: ${e.response?.data?.detail || 'unknown error'}`
  } finally {
    importing.value = false
  }
}

async function remove(s) {
  if (!confirm(`Delete server "${s.name}"?`)) return
  await api.delete(`/servers/${s.id}`)
  await load()
}

async function test(s) {
  testResult.value = { ...testResult.value, [s.id]: { loading: true } }
  const { data } = await api.post(`/servers/${s.id}/test`)
  testResult.value = { ...testResult.value, [s.id]: data }
}

async function sync(s) {
  syncingId.value = s.id
  try { await api.post(`/sync/run/${s.id}`); await load() }
  finally { syncingId.value = null }
}

function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Servers</h1>
    <button v-if="auth.isEditor" class="btn btn-primary" @click="openCreate">+ Add server</button>
  </div>
  <div class="content">
    <div v-if="msg" class="alert alert-success" @click="msg = ''">{{ msg }}</div>
    <div class="card">
      <table>
        <thead><tr><th>Server</th><th>Zone</th><th>Status</th><th>Sync</th><th>Prune</th><th>Last synced</th><th></th></tr></thead>
        <tbody>
          <tr v-for="s in servers" :key="s.id">
            <td>
              <strong>{{ s.name }}</strong>
              <span v-if="!s.enabled" class="badge offline" style="margin-left:6px">disabled</span>
              <div class="muted mono">{{ s.url }}</div>
              <div v-if="testResult[s.id]" class="hint">
                <span v-if="testResult[s.id].loading">Testing…</span>
                <span v-else-if="testResult[s.id].ok" style="color:var(--green-dark)">✓ v{{ testResult[s.id].version }}, {{ testResult[s.id].rewrite_count }} rewrites</span>
                <span v-else style="color:var(--red)">✗ {{ testResult[s.id].error }}</span>
              </div>
            </td>
            <td><span class="badge zone">{{ zoneName(s.zone_id) }}</span></td>
            <td><span class="badge" :class="s.status"><span class="dot"></span>{{ s.status }}</span></td>
            <td>
              <span v-if="s.in_sync" class="badge synced">In sync</span>
              <span v-else class="badge drift">Drift</span>
            </td>
            <td>{{ s.prune ? 'On' : 'Off' }}</td>
            <td class="muted">{{ fmt(s.last_synced) }}</td>
            <td class="row-actions">
              <button class="btn btn-sm" @click="test(s)">Test</button>
              <template v-if="auth.isEditor">
                <button class="btn btn-sm" :disabled="syncingId === s.id" @click="sync(s)">Sync</button>
                <button class="btn btn-sm" @click="openImport(s)">Import</button>
                <button class="btn btn-sm" @click="openEdit(s)">Edit</button>
                <button class="btn btn-sm btn-danger" @click="remove(s)">Delete</button>
              </template>
            </td>
          </tr>
          <tr v-if="!servers.length"><td colspan="7" class="empty">No servers yet. Add your AdGuard Home instances.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <Modal v-if="showModal" :title="editing ? 'Edit server' : 'Add server'" @close="showModal = false">
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div class="form-row">
      <label>Name</label>
      <input v-model="form.name" placeholder="pi-hole-iot" />
    </div>
    <div class="form-row">
      <label>URL</label>
      <input v-model="form.url" placeholder="http://10.0.0.2:3000" />
    </div>
    <div class="form-grid">
      <div class="form-row">
        <label>AdGuard username</label>
        <input v-model="form.username" autocomplete="off" />
      </div>
      <div class="form-row">
        <label>AdGuard password</label>
        <input v-model="form.password" type="password" autocomplete="new-password" :placeholder="editing ? 'unchanged' : ''" />
      </div>
    </div>
    <div class="form-row">
      <label>Zone</label>
      <select v-model="form.zone_id">
        <option :value="null">— Unzoned (global records only) —</option>
        <option v-for="z in zones" :key="z.id" :value="z.id">{{ z.name }}</option>
      </select>
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="enabled" v-model="form.enabled" />
      <label for="enabled" style="margin:0">Enabled (included in reconciliation)</label>
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="prune" v-model="form.prune" />
      <label for="prune" style="margin:0">Prune un-managed rewrites on this server</label>
    </div>
    <div class="hint">Prune removes DNS rewrites on the server that aren't defined here. Leave off to coexist with manually-added entries.</div>
    <template v-if="!editing">
      <div class="form-row checkbox-row" style="margin-top:14px">
        <input type="checkbox" id="import-on-add" v-model="form.import_records" />
        <label for="import-on-add" style="margin:0">Import this server's existing DNS records on add</label>
      </div>
      <div class="form-row" v-if="form.import_records">
        <label>Import as</label>
        <select v-model="form.import_scope">
          <option value="global">Global records (apply to all servers)</option>
          <option value="zone" :disabled="!form.zone_id">Records scoped to this server's zone</option>
        </select>
        <div class="hint">Reads the server's current rewrites into the admin app. Duplicates are skipped.</div>
      </div>
    </template>
    <template #footer>
      <button class="btn" @click="showModal = false">Cancel</button>
      <button class="btn btn-primary" @click="save">Save</button>
    </template>
  </Modal>

  <Modal v-if="importTarget" :title="`Import records from ${importTarget.name}`" @close="importTarget = null">
    <p class="muted" style="margin-top:0">Reads the server's current DNS rewrites into the admin app as records. Existing records (same domain, answer &amp; scope) are skipped.</p>
    <div class="form-row">
      <label>Import as</label>
      <select v-model="importScope">
        <option value="global">Global records (apply to all servers)</option>
        <option value="zone" :disabled="!importTarget.zone_id">Records scoped to this server's zone</option>
      </select>
      <div v-if="!importTarget.zone_id" class="hint">This server isn't in a zone, so only global import is available.</div>
    </div>
    <template #footer>
      <button class="btn" @click="importTarget = null">Cancel</button>
      <button class="btn btn-primary" :disabled="importing" @click="runImport">
        <span v-if="importing" class="spinner"></span><span>Import</span>
      </button>
    </template>
  </Modal>
</template>
