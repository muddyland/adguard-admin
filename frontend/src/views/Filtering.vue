<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import Modal from '../components/Modal.vue'
import ZonePicker from '../components/ZonePicker.vue'
import ZoneBadge from '../components/ZoneBadge.vue'

const auth = useAuth()
const filters = ref([])
const blockedServices = ref([])
const zones = ref([])
const servers = ref([])
const catalog = ref([])
const serviceCatalog = ref([])

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || `#${id}`
const serverName = (id) => servers.value.find((s) => s.id === id)?.name || '—'
const scopeBadge = (s) => (s === 'global' ? 'global' : 'zone')
const serviceLabel = (id) => serviceCatalog.value.find((s) => s.service_id === id)?.name || id

const blocklists = computed(() => filters.value.filter((f) => f.kind === 'blocklist'))
const allowlists = computed(() => filters.value.filter((f) => f.kind === 'allowlist'))
const existingUrls = computed(() => new Set(filters.value.map((f) => f.url)))
const existingServiceIds = computed(() => new Set(blockedServices.value.map((b) => b.service_id)))

async function load() {
  const [f, b, z, s] = await Promise.all([
    api.get('/filters'), api.get('/blocked-services'), api.get('/zones'), api.get('/servers'),
  ])
  filters.value = f.data
  blockedServices.value = b.data
  zones.value = z.data
  servers.value = s.data
}

async function loadCatalogs() {
  const [c, sc] = await Promise.all([api.get('/filters/catalog'), api.get('/blocked-services/catalog')])
  catalog.value = c.data
  serviceCatalog.value = sc.data
}

// ---- Filter list modal (blocklist / allowlist) ----
const showFilter = ref(false)
const editFilter = ref(null)
const fForm = ref({})
const fError = ref('')

function openFilter(f, kind = 'blocklist') {
  editFilter.value = f
  fForm.value = f
    ? { name: f.name, url: f.url, kind: f.kind, scope: f.scope, zone_ids: [...(f.zone_ids || [])], server_id: f.server_id, enabled: f.enabled, description: f.description || '' }
    : { name: '', url: '', kind, scope: 'global', zone_ids: [], server_id: null, enabled: true, description: '' }
  fError.value = ''
  showFilter.value = true
}
async function saveFilter() {
  fError.value = ''
  try {
    if (editFilter.value) await api.patch(`/filters/${editFilter.value.id}`, fForm.value)
    else await api.post('/filters', fForm.value)
    showFilter.value = false
    await load()
  } catch (e) { fError.value = e.response?.data?.detail || 'Save failed' }
}
async function toggleFilter(f) {
  await api.patch(`/filters/${f.id}`, { enabled: !f.enabled }); await load()
}
async function delFilter(f) {
  if (!confirm(`Delete ${f.kind} "${f.name}"?`)) return
  await api.delete(`/filters/${f.id}`); await load()
}

// ---- Popular catalog modal ----
const showCatalog = ref(false)
const catalogKind = ref('blocklist')
const adding = ref('')
const catalogList = computed(() => catalog.value.filter((c) => c.kind === catalogKind.value))

function openCatalog(kind) { catalogKind.value = kind; showCatalog.value = true }
async function addFromCatalog(entry) {
  adding.value = entry.url
  try {
    await api.post('/filters', {
      name: entry.name, url: entry.url, kind: entry.kind, scope: 'global', enabled: true,
      description: entry.description || '',
    })
    await load()
  } finally { adding.value = '' }
}

// ---- Blocked service modal ----
const showBs = ref(false)
const editBs = ref(null)
const bsForm = ref({})
const bsError = ref('')

function openBs(b) {
  editBs.value = b
  bsForm.value = b
    ? { service_id: b.service_id, scope: b.scope, zone_ids: [...(b.zone_ids || [])], server_id: b.server_id, enabled: b.enabled, description: b.description || '' }
    : { service_id: '', scope: 'global', zone_ids: [], server_id: null, enabled: true, description: '' }
  bsError.value = ''
  showBs.value = true
}
async function saveBs() {
  bsError.value = ''
  if (!bsForm.value.service_id) { bsError.value = 'Pick a service'; return }
  try {
    if (editBs.value) await api.patch(`/blocked-services/${editBs.value.id}`, bsForm.value)
    else await api.post('/blocked-services', bsForm.value)
    showBs.value = false
    await load()
  } catch (e) { bsError.value = e.response?.data?.detail || 'Save failed' }
}
async function toggleBs(b) {
  await api.patch(`/blocked-services/${b.id}`, { enabled: !b.enabled }); await load()
}
async function delBs(b) {
  if (!confirm(`Stop blocking "${serviceLabel(b.service_id)}"?`)) return
  await api.delete(`/blocked-services/${b.id}`); await load()
}

// ---- Popular services modal ----
const showServices = ref(false)
const picked = ref(new Set())
const savingServices = ref(false)
function openServices() { picked.value = new Set(); showServices.value = true }
function togglePick(id) {
  const s = new Set(picked.value)
  s.has(id) ? s.delete(id) : s.add(id)
  picked.value = s
}
async function addServices() {
  savingServices.value = true
  try {
    for (const id of picked.value) {
      await api.post('/blocked-services', { service_id: id, scope: 'global', enabled: true })
    }
    showServices.value = false
    await load()
  } finally { savingServices.value = false }
}

onMounted(async () => { await Promise.all([load(), loadCatalogs()]) })
</script>

<template>
  <div class="topbar">
    <h1>Filtering</h1>
  </div>
  <div class="content">
    <p class="muted" style="margin-top:0">
      Blocklists, allowlists and blocked services are applied to each server during sync — but only to
      servers with <strong>“Manage filtering”</strong> enabled (set it on the Servers page).
      Existing lists on a server are left in place unless that server has <strong>Prune</strong> on.
    </p>

    <!-- Blocklists -->
    <div class="card" style="margin-bottom:24px">
      <div class="card-header">
        <h2>Blocklists</h2>
        <div class="flex" style="gap:8px" v-if="auth.isEditor">
          <button class="btn btn-sm" @click="openCatalog('blocklist')">★ Add popular</button>
          <button class="btn btn-primary btn-sm" @click="openFilter(null, 'blocklist')">+ Add blocklist</button>
        </div>
      </div>
      <table>
        <thead><tr><th>Name</th><th>URL</th><th>Scope</th><th>Applies to</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          <tr v-for="f in blocklists" :key="f.id">
            <td><strong>{{ f.name }}</strong><div v-if="f.description" class="muted">{{ f.description }}</div></td>
            <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" :title="f.url">{{ f.url }}</td>
            <td><span class="badge" :class="scopeBadge(f.scope)">{{ f.scope }}</span></td>
            <td>
              <span v-if="f.scope === 'global'" class="muted">All servers</span>
              <span v-else-if="f.scope === 'server'">{{ serverName(f.server_id) }}</span>
              <span v-else class="zone-pills"><ZoneBadge v-for="id in f.zone_ids" :key="id" :id="id" :label="zoneName(id)" /></span>
            </td>
            <td>
              <button class="badge" :class="f.enabled ? 'synced' : 'offline'" :disabled="!auth.isEditor"
                      style="cursor:pointer;border:none" @click="toggleFilter(f)">{{ f.enabled ? 'on' : 'off' }}</button>
            </td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="openFilter(f)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="delFilter(f)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!blocklists.length"><td colspan="6" class="empty">No blocklists yet. Add a popular list to get started.</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Allowlists -->
    <div class="card" style="margin-bottom:24px">
      <div class="card-header">
        <h2>Allowlists</h2>
        <div class="flex" style="gap:8px" v-if="auth.isEditor">
          <button class="btn btn-sm" @click="openCatalog('allowlist')">★ Add popular</button>
          <button class="btn btn-primary btn-sm" @click="openFilter(null, 'allowlist')">+ Add allowlist</button>
        </div>
      </div>
      <table>
        <thead><tr><th>Name</th><th>URL</th><th>Scope</th><th>Applies to</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          <tr v-for="f in allowlists" :key="f.id">
            <td><strong>{{ f.name }}</strong><div v-if="f.description" class="muted">{{ f.description }}</div></td>
            <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" :title="f.url">{{ f.url }}</td>
            <td><span class="badge" :class="scopeBadge(f.scope)">{{ f.scope }}</span></td>
            <td>
              <span v-if="f.scope === 'global'" class="muted">All servers</span>
              <span v-else-if="f.scope === 'server'">{{ serverName(f.server_id) }}</span>
              <span v-else class="zone-pills"><ZoneBadge v-for="id in f.zone_ids" :key="id" :id="id" :label="zoneName(id)" /></span>
            </td>
            <td>
              <button class="badge" :class="f.enabled ? 'synced' : 'offline'" :disabled="!auth.isEditor"
                      style="cursor:pointer;border:none" @click="toggleFilter(f)">{{ f.enabled ? 'on' : 'off' }}</button>
            </td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="openFilter(f)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="delFilter(f)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!allowlists.length"><td colspan="6" class="empty">No allowlists. Allowlists exempt domains that other lists would block.</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Blocked services -->
    <div class="card">
      <div class="card-header">
        <h2>Blocked services</h2>
        <div class="flex" style="gap:8px" v-if="auth.isEditor">
          <button class="btn btn-sm" @click="openServices">★ Add popular</button>
          <button class="btn btn-primary btn-sm" @click="openBs(null)">+ Add service</button>
        </div>
      </div>
      <table>
        <thead><tr><th>Service</th><th>Scope</th><th>Applies to</th><th>Enabled</th><th></th></tr></thead>
        <tbody>
          <tr v-for="b in blockedServices" :key="b.id">
            <td><strong>{{ serviceLabel(b.service_id) }}</strong> <span class="muted mono">{{ b.service_id }}</span></td>
            <td><span class="badge" :class="scopeBadge(b.scope)">{{ b.scope }}</span></td>
            <td>
              <span v-if="b.scope === 'global'" class="muted">All servers</span>
              <span v-else-if="b.scope === 'server'">{{ serverName(b.server_id) }}</span>
              <span v-else class="zone-pills"><ZoneBadge v-for="id in b.zone_ids" :key="id" :id="id" :label="zoneName(id)" /></span>
            </td>
            <td>
              <button class="badge" :class="b.enabled ? 'synced' : 'offline'" :disabled="!auth.isEditor"
                      style="cursor:pointer;border:none" @click="toggleBs(b)">{{ b.enabled ? 'on' : 'off' }}</button>
            </td>
            <td class="row-actions" v-if="auth.isEditor">
              <button class="btn btn-sm" @click="openBs(b)">Edit</button>
              <button class="btn btn-sm btn-danger" @click="delBs(b)">Delete</button>
            </td>
            <td v-else></td>
          </tr>
          <tr v-if="!blockedServices.length"><td colspan="5" class="empty">No services blocked. Add popular services like YouTube or TikTok.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Filter modal -->
  <Modal v-if="showFilter" :title="editFilter ? 'Edit list' : (fForm.kind === 'allowlist' ? 'Add allowlist' : 'Add blocklist')" @close="showFilter = false">
    <div v-if="fError" class="alert alert-error">{{ fError }}</div>
    <div class="form-row">
      <label>Type</label>
      <select v-model="fForm.kind">
        <option value="blocklist">Blocklist — blocks matching domains</option>
        <option value="allowlist">Allowlist — exempts domains from blocking</option>
      </select>
    </div>
    <div class="form-row">
      <label>Name</label>
      <input v-model="fForm.name" placeholder="AdGuard DNS filter" />
    </div>
    <div class="form-row">
      <label>URL</label>
      <input v-model="fForm.url" placeholder="https://example.com/list.txt" />
    </div>
    <div class="form-row">
      <label>Scope</label>
      <select v-model="fForm.scope">
        <option value="global">Global — every server</option>
        <option value="zone">Zone — servers in selected zones</option>
        <option value="server">Server — one server</option>
      </select>
    </div>
    <div class="form-row" v-if="fForm.scope === 'zone'">
      <label>Zones</label>
      <ZonePicker v-model="fForm.zone_ids" :zones="zones" />
    </div>
    <div class="form-row" v-if="fForm.scope === 'server'">
      <label>Server</label>
      <select v-model="fForm.server_id">
        <option :value="null" disabled>Select a server…</option>
        <option v-for="s in servers" :key="s.id" :value="s.id">{{ s.name }}</option>
      </select>
    </div>
    <div class="form-row">
      <label>Description</label>
      <input v-model="fForm.description" placeholder="Optional" />
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="f-en" v-model="fForm.enabled" /><label for="f-en" style="margin:0">Enabled</label>
    </div>
    <template #footer>
      <button class="btn" @click="showFilter = false">Cancel</button>
      <button class="btn btn-primary" @click="saveFilter">Save</button>
    </template>
  </Modal>

  <!-- Popular catalog modal -->
  <Modal v-if="showCatalog" :title="catalogKind === 'allowlist' ? 'Popular allowlists' : 'Popular blocklists'" @close="showCatalog = false">
    <p class="muted" style="margin-top:0">Added as global lists (every server). You can re-scope them afterwards.</p>
    <div class="catalog">
      <div v-for="c in catalogList" :key="c.url" class="catalog-row">
        <div class="catalog-info">
          <div><strong>{{ c.name }}</strong> <span v-if="c.recommended" class="badge global">recommended</span></div>
          <div class="muted">{{ c.description }}</div>
          <div class="mono muted" style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ c.url }}</div>
        </div>
        <button class="btn btn-sm" :class="existingUrls.has(c.url) ? '' : 'btn-primary'"
                :disabled="existingUrls.has(c.url) || adding === c.url" @click="addFromCatalog(c)">
          {{ existingUrls.has(c.url) ? 'Added ✓' : (adding === c.url ? 'Adding…' : 'Add') }}
        </button>
      </div>
    </div>
    <template #footer>
      <button class="btn btn-primary" @click="showCatalog = false">Done</button>
    </template>
  </Modal>

  <!-- Blocked service modal -->
  <Modal v-if="showBs" :title="editBs ? 'Edit blocked service' : 'Add blocked service'" @close="showBs = false">
    <div v-if="bsError" class="alert alert-error">{{ bsError }}</div>
    <div class="form-row">
      <label>Service</label>
      <input v-model="bsForm.service_id" list="service-catalog" placeholder="youtube" />
      <datalist id="service-catalog">
        <option v-for="s in serviceCatalog" :key="s.service_id" :value="s.service_id">{{ s.name }}</option>
      </datalist>
      <div class="hint">AdGuard service id (e.g. <span class="mono">youtube</span>, <span class="mono">tiktok</span>). Pick from the list or type any valid id.</div>
    </div>
    <div class="form-row">
      <label>Scope</label>
      <select v-model="bsForm.scope">
        <option value="global">Global — every server</option>
        <option value="zone">Zone — servers in selected zones</option>
        <option value="server">Server — one server</option>
      </select>
    </div>
    <div class="form-row" v-if="bsForm.scope === 'zone'">
      <label>Zones</label>
      <ZonePicker v-model="bsForm.zone_ids" :zones="zones" />
    </div>
    <div class="form-row" v-if="bsForm.scope === 'server'">
      <label>Server</label>
      <select v-model="bsForm.server_id">
        <option :value="null" disabled>Select a server…</option>
        <option v-for="s in servers" :key="s.id" :value="s.id">{{ s.name }}</option>
      </select>
    </div>
    <div class="form-row checkbox-row">
      <input type="checkbox" id="bs-en" v-model="bsForm.enabled" /><label for="bs-en" style="margin:0">Enabled</label>
    </div>
    <template #footer>
      <button class="btn" @click="showBs = false">Cancel</button>
      <button class="btn btn-primary" @click="saveBs">Save</button>
    </template>
  </Modal>

  <!-- Popular services modal -->
  <Modal v-if="showServices" title="Block popular services" @close="showServices = false">
    <p class="muted" style="margin-top:0">Select services to block on every server (global scope).</p>
    <div class="service-grid">
      <label v-for="s in serviceCatalog" :key="s.service_id" class="service-opt"
             :class="{ disabled: existingServiceIds.has(s.service_id) }">
        <input type="checkbox" :disabled="existingServiceIds.has(s.service_id)"
               :checked="picked.has(s.service_id)" @change="togglePick(s.service_id)" />
        <span>{{ s.name }}</span>
        <span v-if="existingServiceIds.has(s.service_id)" class="muted" style="font-size:11px">added</span>
      </label>
    </div>
    <template #footer>
      <button class="btn" @click="showServices = false">Cancel</button>
      <button class="btn btn-primary" :disabled="!picked.size || savingServices" @click="addServices">
        {{ savingServices ? 'Adding…' : `Block ${picked.size || ''} selected` }}
      </button>
    </template>
  </Modal>
</template>

<style scoped>
.catalog { display: flex; flex-direction: column; gap: 8px; max-height: 60vh; overflow-y: auto; }
.catalog-row { display: flex; align-items: center; gap: 12px; padding: 10px; border: 1px solid var(--border); border-radius: 8px; }
.catalog-info { min-width: 0; flex: 1; }
.service-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 6px; max-height: 60vh; overflow-y: auto; }
.service-opt { display: flex; align-items: center; gap: 6px; padding: 6px 8px; border: 1px solid var(--border); border-radius: 6px; cursor: pointer; }
.service-opt.disabled { opacity: 0.55; cursor: not-allowed; }
</style>
