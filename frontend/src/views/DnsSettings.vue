<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'
import ZonePicker from '../components/ZonePicker.vue'

const auth = useAuth()
const upstreams = ref([])
const forwardZones = ref([])
const zones = ref([])
const servers = ref([])

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || `#${id}`
const zoneNames = (ids) => (ids || []).map(zoneName).join(', ') || '—'
const serverName = (id) => servers.value.find((s) => s.id === id)?.name || '—'
const target = (row) =>
  row.scope === 'global' ? 'All servers' : row.scope === 'zone' ? zoneNames(row.zone_ids) : serverName(row.server_id)

async function load() {
  const [u, f, z, s] = await Promise.all([
    api.get('/upstreams'), api.get('/forward-zones'), api.get('/zones'), api.get('/servers'),
  ])
  upstreams.value = u.data
  forwardZones.value = f.data
  zones.value = z.data
  servers.value = s.data
}

// ---- Upstream modal ----
const showUp = ref(false)
const editUp = ref(null)
const upForm = ref({})
const upError = ref('')

function openUp(u) {
  editUp.value = u
  upForm.value = u
    ? { address: u.address, scope: u.scope, zone_ids: [...(u.zone_ids || [])], server_id: u.server_id, enabled: u.enabled, description: u.description || '' }
    : { address: '', scope: 'global', zone_ids: [], server_id: null, enabled: true, description: '' }
  upError.value = ''
  showUp.value = true
}
async function saveUp() {
  upError.value = ''
  try {
    if (editUp.value) await api.patch(`/upstreams/${editUp.value.id}`, upForm.value)
    else await api.post('/upstreams', upForm.value)
    showUp.value = false
    await load()
  } catch (e) { upError.value = e.response?.data?.detail || 'Save failed' }
}
async function delUp(u) {
  if (!confirm(`Delete upstream ${u.address}?`)) return
  await api.delete(`/upstreams/${u.id}`); await load()
}

// ---- Forward zone modal ----
const showFz = ref(false)
const editFz = ref(null)
const fzForm = ref({})
const fzError = ref('')

function openFz(f) {
  editFz.value = f
  fzForm.value = f
    ? { domains: f.domains, upstreams: f.upstreams, scope: f.scope, zone_ids: [...(f.zone_ids || [])], server_id: f.server_id, enabled: f.enabled, description: f.description || '' }
    : { domains: '', upstreams: '', scope: 'global', zone_ids: [], server_id: null, enabled: true, description: '' }
  fzError.value = ''
  showFz.value = true
}
async function saveFz() {
  fzError.value = ''
  try {
    if (editFz.value) await api.patch(`/forward-zones/${editFz.value.id}`, fzForm.value)
    else await api.post('/forward-zones', fzForm.value)
    showFz.value = false
    await load()
  } catch (e) { fzError.value = e.response?.data?.detail || 'Save failed' }
}
async function delFz(f) {
  if (!confirm(`Delete forward zone for ${f.domains}?`)) return
  await api.delete(`/forward-zones/${f.id}`); await load()
}

const scopeBadge = (s) => (s === 'global' ? 'global' : 'zone')

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>DNS Settings</h1>
  </div>
  <div class="content">
    <p class="muted" style="margin-top:0">
      Upstreams and forward zones are applied to each server during sync — but only to servers
      with <strong>“Manage upstreams”</strong> enabled (set it on the Servers page).
    </p>

    <!-- Upstreams -->
    <div class="card" style="margin-bottom:24px">
      <div class="card-header">
        <h2>Upstream DNS servers</h2>
        <button v-if="auth.isEditor" class="btn btn-primary btn-sm" @click="openUp(null)">+ Add upstream</button>
      </div>
      <table>
        <thead><tr><th>Address</th><th>Scope</th><th>Applies to</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          <tr v-for="u in upstreams" :key="u.id">
            <td class="mono"><strong>{{ u.address }}</strong><div v-if="u.description" class="muted">{{ u.description }}</div></td>
            <td><span class="badge" :class="scopeBadge(u.scope)">{{ u.scope }}</span></td>
            <td>{{ target(u) }}</td>
            <td><span class="badge" :class="u.enabled ? 'synced' : 'offline'">{{ u.enabled ? 'on' : 'off' }}</span></td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="openUp(u)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="delUp(u)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!upstreams.length"><td colspan="5" class="empty">No upstreams defined. Servers keep their own config.</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Forward zones -->
    <div class="card">
      <div class="card-header">
        <h2>Forward zones (per-domain upstreams)</h2>
        <button v-if="auth.isEditor" class="btn btn-primary btn-sm" @click="openFz(null)">+ Add forward zone</button>
      </div>
      <table>
        <thead><tr><th>Domains</th><th>Forward to</th><th>Scope</th><th>Applies to</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          <tr v-for="f in forwardZones" :key="f.id">
            <td class="mono"><strong>{{ f.domains }}</strong><div v-if="f.description" class="muted">{{ f.description }}</div></td>
            <td class="mono">{{ f.upstreams.split(/[\s,]+/).join(', ') }}</td>
            <td><span class="badge" :class="scopeBadge(f.scope)">{{ f.scope }}</span></td>
            <td>{{ target(f) }}</td>
            <td><span class="badge" :class="f.enabled ? 'synced' : 'offline'">{{ f.enabled ? 'on' : 'off' }}</span></td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="openFz(f)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="delFz(f)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!forwardZones.length"><td colspan="6" class="empty">No forward zones. Add one to route a domain to specific upstreams.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Upstream modal -->
  <Modal v-if="showUp" :title="editUp ? 'Edit upstream' : 'Add upstream'" @close="showUp = false">
    <div v-if="upError" class="alert alert-error">{{ upError }}</div>
    <div class="form-row">
      <label>Address</label>
      <input v-model="upForm.address" placeholder="1.1.1.1  or  https://dns.google/dns-query" />
    </div>
    <div class="form-row">
      <label>Scope</label>
      <select v-model="upForm.scope">
        <option value="global">Global — every server</option>
        <option value="zone">Zone — servers in selected zones</option>
        <option value="server">Server — one server</option>
      </select>
    </div>
    <div class="form-row" v-if="upForm.scope === 'zone'">
      <label>Zones</label>
      <ZonePicker v-model="upForm.zone_ids" :zones="zones" />
    </div>
    <div class="form-row" v-if="upForm.scope === 'server'">
      <label>Server</label>
      <select v-model="upForm.server_id">
        <option :value="null" disabled>Select a server…</option>
        <option v-for="s in servers" :key="s.id" :value="s.id">{{ s.name }}</option>
      </select>
    </div>
    <div class="form-row">
      <label>Description</label>
      <input v-model="upForm.description" placeholder="Optional" />
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="up-en" v-model="upForm.enabled" /><label for="up-en" style="margin:0">Enabled</label>
    </div>
    <template #footer>
      <button class="btn" @click="showUp = false">Cancel</button>
      <button class="btn btn-primary" @click="saveUp">Save</button>
    </template>
  </Modal>

  <!-- Forward zone modal -->
  <Modal v-if="showFz" :title="editFz ? 'Edit forward zone' : 'Add forward zone'" @close="showFz = false">
    <div v-if="fzError" class="alert alert-error">{{ fzError }}</div>
    <div class="form-row">
      <label>Domains</label>
      <input v-model="fzForm.domains" placeholder="internal.lan corp.lan" />
      <div class="hint">One or more domains, space-separated. Queries for these go to the upstreams below.</div>
    </div>
    <div class="form-row">
      <label>Forward to (upstreams)</label>
      <textarea v-model="fzForm.upstreams" rows="3" placeholder="10.0.0.53&#10;10.0.0.54"></textarea>
      <div class="hint">One upstream per line (or space-separated). Rendered as <span class="mono">[/domain/]upstream</span>.</div>
    </div>
    <div class="form-row">
      <label>Scope</label>
      <select v-model="fzForm.scope">
        <option value="global">Global — every server</option>
        <option value="zone">Zone — servers in selected zones</option>
        <option value="server">Server — one server</option>
      </select>
    </div>
    <div class="form-row" v-if="fzForm.scope === 'zone'">
      <label>Zones</label>
      <ZonePicker v-model="fzForm.zone_ids" :zones="zones" />
    </div>
    <div class="form-row" v-if="fzForm.scope === 'server'">
      <label>Server</label>
      <select v-model="fzForm.server_id">
        <option :value="null" disabled>Select a server…</option>
        <option v-for="s in servers" :key="s.id" :value="s.id">{{ s.name }}</option>
      </select>
    </div>
    <div class="form-row">
      <label>Description</label>
      <input v-model="fzForm.description" placeholder="Optional" />
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="fz-en" v-model="fzForm.enabled" /><label for="fz-en" style="margin:0">Enabled</label>
    </div>
    <template #footer>
      <button class="btn" @click="showFz = false">Cancel</button>
      <button class="btn btn-primary" @click="saveFz">Save</button>
    </template>
  </Modal>
</template>
