<script setup>
import { ref, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'

const auth = useAuth()
const zones = ref([])
const showModal = ref(false)
const editing = ref(null)
const form = ref({ name: '', slug: '', description: '' })
const error = ref('')

async function load() { zones.value = (await api.get('/zones')).data }

function openCreate() {
  editing.value = null
  form.value = { name: '', slug: '', description: '' }
  error.value = ''
  showModal.value = true
}
function openEdit(z) {
  editing.value = z
  form.value = { name: z.name, slug: z.slug, description: z.description || '' }
  error.value = ''
  showModal.value = true
}

async function save() {
  error.value = ''
  try {
    if (editing.value) await api.patch(`/zones/${editing.value.id}`, form.value)
    else await api.post('/zones', form.value)
    showModal.value = false
    await load()
  } catch (e) { error.value = e.response?.data?.detail || 'Save failed' }
}

async function remove(z) {
  if (!confirm(`Delete zone "${z.name}"?`)) return
  try { await api.delete(`/zones/${z.id}`); await load() }
  catch (e) { alert(e.response?.data?.detail || 'Delete failed') }
}

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Zones</h1>
    <button v-if="auth.isEditor" class="btn btn-primary" @click="openCreate">+ Add zone</button>
  </div>
  <div class="content">
    <div class="card">
      <table>
        <thead><tr><th>Name</th><th>Slug</th><th>Description</th><th>Servers</th><th>Records</th><th></th></tr></thead>
        <tbody>
          <tr v-for="z in zones" :key="z.id">
            <td><strong>{{ z.name }}</strong></td>
            <td><span class="badge zone">{{ z.slug }}</span></td>
            <td class="muted">{{ z.description || '—' }}</td>
            <td>{{ z.server_count }}</td>
            <td>{{ z.record_count }}</td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="openEdit(z)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="remove(z)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!zones.length"><td colspan="6" class="empty">No zones yet. Create on-prem, cloud, iot-vlan…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <Modal v-if="showModal" :title="editing ? 'Edit zone' : 'Add zone'" @close="showModal = false">
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div class="form-row">
      <label>Name</label>
      <input v-model="form.name" placeholder="IoT VLAN" />
    </div>
    <div class="form-row">
      <label>Slug</label>
      <input v-model="form.slug" placeholder="auto-generated from name" />
      <div class="hint">Used internally. Leave blank to derive from the name.</div>
    </div>
    <div class="form-row">
      <label>Description</label>
      <textarea v-model="form.description" rows="2" placeholder="Optional"></textarea>
    </div>
    <template #footer>
      <button class="btn" @click="showModal = false">Cancel</button>
      <button class="btn btn-primary" @click="save">Save</button>
    </template>
  </Modal>
</template>
