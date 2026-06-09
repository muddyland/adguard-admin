<script setup>
import { ref, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'

const auth = useAuth()
const users = ref([])
const showModal = ref(false)
const editing = ref(null)
const form = ref({})
const error = ref('')

async function load() { users.value = (await api.get('/users')).data }

function openCreate() {
  editing.value = null
  form.value = { username: '', email: '', password: '', role: 'viewer' }
  error.value = ''
  showModal.value = true
}
function openEdit(u) {
  editing.value = u
  form.value = { email: u.email || '', role: u.role, is_active: u.is_active, password: '' }
  error.value = ''
  showModal.value = true
}

async function save() {
  error.value = ''
  try {
    if (editing.value) {
      const payload = { ...form.value }
      if (!payload.password) delete payload.password
      await api.patch(`/users/${editing.value.id}`, payload)
    } else {
      await api.post('/users', form.value)
    }
    showModal.value = false
    await load()
  } catch (e) { error.value = e.response?.data?.detail || 'Save failed' }
}

async function remove(u) {
  if (!confirm(`Delete user "${u.username}"?`)) return
  try { await api.delete(`/users/${u.id}`); await load() }
  catch (e) { alert(e.response?.data?.detail || 'Delete failed') }
}

function fmt(d) { return d ? new Date(d).toLocaleDateString() : '—' }

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Users</h1>
    <button class="btn btn-primary" @click="openCreate">+ Add user</button>
  </div>
  <div class="content">
    <div class="card">
      <table>
        <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Type</th><th>Status</th><th>Created</th><th></th></tr></thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td><strong>{{ u.username }}</strong><span v-if="u.id === auth.user?.id" class="muted"> (you)</span></td>
            <td class="muted">{{ u.email || '—' }}</td>
            <td><span class="badge" :class="`role-${u.role}`">{{ u.role }}</span></td>
            <td class="muted">{{ u.oidc_sub ? 'OIDC' : 'Local' }}</td>
            <td>
              <span v-if="u.is_active" class="badge synced">active</span>
              <span v-else class="badge offline">disabled</span>
            </td>
            <td class="muted">{{ fmt(u.created_at) }}</td>
            <td class="row-actions">
              <button class="btn btn-sm" @click="openEdit(u)">Edit</button>
              <button class="btn btn-sm btn-danger" :disabled="u.id === auth.user?.id" @click="remove(u)">Delete</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <Modal v-if="showModal" :title="editing ? `Edit ${editing.username}` : 'Add user'" @close="showModal = false">
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div v-if="!editing" class="form-row">
      <label>Username</label>
      <input v-model="form.username" autocomplete="off" />
    </div>
    <div class="form-row">
      <label>Email</label>
      <input v-model="form.email" type="email" />
    </div>
    <div class="form-row">
      <label>Role</label>
      <select v-model="form.role">
        <option value="viewer">Viewer — read-only</option>
        <option value="editor">Editor — manage zones, servers, records</option>
        <option value="admin">Admin — full control incl. users</option>
      </select>
    </div>
    <div class="form-row">
      <label>{{ editing ? 'New password (leave blank to keep)' : 'Password' }}</label>
      <input v-model="form.password" type="password" autocomplete="new-password" />
    </div>
    <div v-if="editing" class="form-row checkbox-row">
      <input type="checkbox" id="active" v-model="form.is_active" />
      <label for="active" style="margin:0">Active</label>
    </div>
    <template #footer>
      <button class="btn" @click="showModal = false">Cancel</button>
      <button class="btn btn-primary" @click="save">Save</button>
    </template>
  </Modal>
</template>
