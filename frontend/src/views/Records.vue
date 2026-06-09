<script setup>
import { ref, onMounted, computed } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'
import ZonePicker from '../components/ZonePicker.vue'
import ZoneBadge from '../components/ZoneBadge.vue'

const auth = useAuth()
const records = ref([])
const zones = ref([])
const showModal = ref(false)
const editing = ref(null)
const form = ref({})
const error = ref('')
const filterScope = ref('')
const filterZone = ref('')
const search = ref('')

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || `#${id}`
const zoneNames = (ids) => (ids || []).map(zoneName).join(', ') || '—'

const filtered = computed(() =>
  records.value.filter((r) => {
    if (filterScope.value && r.scope !== filterScope.value) return false
    if (filterZone.value && !(r.zone_ids || []).includes(Number(filterZone.value))) return false
    if (search.value && !`${r.domain} ${r.answer}`.toLowerCase().includes(search.value.toLowerCase())) return false
    return true
  })
)

async function load() {
  const [r, z] = await Promise.all([api.get('/records'), api.get('/zones')])
  records.value = r.data
  zones.value = z.data
}

function openCreate() {
  editing.value = null
  form.value = { domain: '', answer: '', scope: 'global', zone_ids: [], enabled: true, description: '' }
  error.value = ''
  showModal.value = true
}
function openEdit(r) {
  editing.value = r
  form.value = { domain: r.domain, answer: r.answer, scope: r.scope, zone_ids: [...(r.zone_ids || [])], enabled: r.enabled, description: r.description || '' }
  error.value = ''
  showModal.value = true
}

async function save() {
  error.value = ''
  try {
    if (editing.value) await api.patch(`/records/${editing.value.id}`, form.value)
    else await api.post('/records', form.value)
    showModal.value = false
    await load()
  } catch (e) { error.value = e.response?.data?.detail || 'Save failed' }
}

async function toggle(r) {
  await api.patch(`/records/${r.id}`, { enabled: !r.enabled })
  await load()
}

async function remove(r) {
  if (!confirm(`Delete ${r.domain} → ${r.answer}?`)) return
  await api.delete(`/records/${r.id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>DNS Records</h1>
    <button v-if="auth.isEditor" class="btn btn-primary" @click="openCreate">+ Add record</button>
  </div>
  <div class="content">
    <div class="toolbar">
      <div class="filters">
        <input v-model="search" placeholder="Search domain or answer…" style="min-width:240px" />
        <select v-model="filterScope">
          <option value="">All scopes</option>
          <option value="global">Global</option>
          <option value="zone">Zone</option>
        </select>
        <select v-model="filterZone">
          <option value="">All zones</option>
          <option v-for="z in zones" :key="z.id" :value="String(z.id)">{{ z.name }}</option>
        </select>
      </div>
      <span class="muted">{{ filtered.length }} of {{ records.length }}</span>
    </div>

    <div class="card">
      <table>
        <thead><tr><th>Domain</th><th>Answer</th><th>Scope</th><th>Zones</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          <tr v-for="r in filtered" :key="r.id">
            <td class="mono"><strong>{{ r.domain }}</strong><div v-if="r.description" class="muted">{{ r.description }}</div></td>
            <td class="mono">{{ r.answer }}</td>
            <td><span class="badge" :class="r.scope === 'global' ? 'global' : 'zone'">{{ r.scope }}</span></td>
            <td>
              <span v-if="r.scope !== 'zone'" class="muted">All</span>
              <span v-else class="zone-pills">
                <ZoneBadge v-for="id in r.zone_ids" :key="id" :id="id" :label="zoneName(id)" />
              </span>
            </td>
            <td>
              <span v-if="r.enabled" class="badge synced">on</span>
              <span v-else class="badge offline">off</span>
            </td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="toggle(r)">{{ r.enabled ? 'Disable' : 'Enable' }}</button>
              <button class="btn btn-sm" @click="openEdit(r)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="remove(r)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!filtered.length"><td colspan="6" class="empty">No DNS records match.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <Modal v-if="showModal" :title="editing ? 'Edit record' : 'Add DNS record'" @close="showModal = false">
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div class="form-grid">
      <div class="form-row">
        <label>Domain</label>
        <input v-model="form.domain" placeholder="nas.home.lan" />
      </div>
      <div class="form-row">
        <label>Answer (IP or host)</label>
        <input v-model="form.answer" placeholder="10.0.0.5" />
      </div>
    </div>
    <div class="form-row">
      <label>Scope</label>
      <select v-model="form.scope">
        <option value="global">Global — applies to every server</option>
        <option value="zone">Zone — only servers in selected zones</option>
      </select>
    </div>
    <div class="form-row" v-if="form.scope === 'zone'">
      <label>Zones</label>
      <ZonePicker v-model="form.zone_ids" :zones="zones" />
    </div>
    <div class="form-row">
      <label>Description</label>
      <input v-model="form.description" placeholder="Optional" />
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="rec-enabled" v-model="form.enabled" />
      <label for="rec-enabled" style="margin:0">Enabled</label>
    </div>
    <template #footer>
      <button class="btn" @click="showModal = false">Cancel</button>
      <button class="btn btn-primary" @click="save">Save</button>
    </template>
  </Modal>
</template>
