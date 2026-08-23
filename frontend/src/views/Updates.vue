<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api'
import { useAuth } from '../stores/auth'
import ZoneBadge from '../components/ZoneBadge.vue'

const auth = useAuth()
const data = ref(null)
const zones = ref([])
const busy = ref('')          // '' | 'check' | 'run' | server id
const msg = ref('')
const error = ref('')
const copied = ref(false)

const servers = computed(() => data.value?.servers || [])
const outdated = computed(() => servers.value.filter((s) => s.update_available))
const managed = computed(() => servers.value.filter((s) => s.auto_update))
const failed = computed(() => servers.value.filter((s) => s.update_state === 'failed'))
// A server whose own version check is off never reports a new release, so it
// looks up to date forever. Call that out rather than letting it hide.
const checksOff = computed(() => servers.value.filter((s) => s.update_check_disabled))
// Boxes this app cannot upgrade itself — they need the on-box updater.
const delegated = computed(() =>
  servers.value.filter((s) => s.install_method === 'docker' || s.update_state === 'delegated')
)

const zoneName = (id) => zones.value.find((z) => z.id === id)?.name || 'Unzoned'

async function load() {
  const [u, z] = await Promise.all([api.get('/updates'), api.get('/zones')])
  data.value = u.data
  zones.value = z.data
}

async function checkAll() {
  busy.value = 'check'
  error.value = ''
  try {
    const { data: rows } = await api.post('/updates/check')
    const n = rows.filter((r) => r.update_available).length
    msg.value = n
      ? `${n} of ${rows.length} server(s) have an update available.`
      : `All ${rows.length} server(s) are up to date.`
    await load()
  } catch (e) {
    error.value = e.response?.data?.detail || 'Version check failed'
  } finally {
    busy.value = ''
  }
}

async function runAll() {
  if (!confirm('Update every eligible server now? Each one restarts AdGuard Home, briefly interrupting DNS.')) return
  busy.value = 'run'
  error.value = ''
  try {
    const { data: outcomes } = await api.post('/updates/run', null, { params: { force: true } })
    msg.value = outcomes.length ? summarise(outcomes) : 'Nothing to update.'
    await load()
  } catch (e) {
    error.value = e.response?.data?.detail || 'Update run failed'
  } finally {
    busy.value = ''
  }
}

async function runOne(s) {
  if (!confirm(`Update ${s.name} to ${s.latest_version} now? AdGuard Home restarts, briefly interrupting DNS on this server.`)) return
  busy.value = s.id
  error.value = ''
  try {
    const { data: outcome } = await api.post(`/updates/${s.id}/run`)
    msg.value = `${outcome.server_name}: ${outcome.message}`
    await load()
  } catch (e) {
    error.value = e.response?.data?.detail || 'Update failed'
  } finally {
    busy.value = ''
  }
}

function summarise(outcomes) {
  const by = (state) => outcomes.filter((o) => o.state === state).length
  const parts = []
  if (by('succeeded')) parts.push(`${by('succeeded')} updated`)
  if (by('delegated')) parts.push(`${by('delegated')} left to their on-box updater`)
  if (by('failed')) parts.push(`${by('failed')} failed`)
  if (by('idle')) parts.push(`${by('idle')} already current`)
  return parts.join(', ') + '.'
}

async function toggleAuto(s) {
  await api.patch(`/servers/${s.id}`, { auto_update: !s.auto_update })
  await load()
}

async function copyCommand() {
  try {
    await navigator.clipboard.writeText(data.value.docker_agent_command)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch { /* clipboard blocked */ }
}

function stateBadge(s) {
  if (s.update_state === 'succeeded') return { cls: 'synced', text: 'updated' }
  if (s.update_state === 'failed') return { cls: 'error', text: 'failed' }
  if (s.update_state === 'delegated') return { cls: 'global', text: 'on-box updater' }
  if (s.update_state === 'running') return { cls: 'drift', text: 'updating…' }
  return null
}

function fmt(d) { return d ? new Date(d).toLocaleString() : '—' }

onMounted(load)
</script>

<template>
  <div class="topbar">
    <h1>Updates</h1>
    <div class="flex" style="gap:8px">
      <button v-if="auth.isEditor" class="btn" :disabled="busy === 'check'" @click="checkAll">
        <span v-if="busy === 'check'" class="spinner"></span><span>Check for updates</span>
      </button>
      <button v-if="auth.isEditor" class="btn btn-primary" :disabled="busy === 'run' || !outdated.length" @click="runAll">
        <span v-if="busy === 'run'" class="spinner"></span><span>Update all eligible</span>
      </button>
    </div>
  </div>

  <div class="content" v-if="data">
    <div v-if="msg" class="alert alert-success" @click="msg = ''">{{ msg }}</div>
    <div v-if="error" class="alert alert-error" @click="error = ''">{{ error }}</div>

    <div class="stats-grid">
      <div class="stat"><div class="value">{{ servers.length }}</div><div class="label">Servers</div></div>
      <div class="stat">
        <div class="value" :class="outdated.length ? 'red' : 'green'">{{ outdated.length }}</div>
        <div class="label">Updates available</div>
      </div>
      <div class="stat"><div class="value">{{ managed.length }}</div><div class="label">Auto-update on</div></div>
      <div class="stat">
        <div class="value" :class="failed.length ? 'red' : ''">{{ failed.length }}</div>
        <div class="label">Failed attempts</div>
      </div>
      <div class="stat">
        <div class="value" :class="checksOff.length ? 'red' : ''">{{ checksOff.length }}</div>
        <div class="label">Update checks off</div>
      </div>
    </div>

    <div v-if="checksOff.length" class="alert alert-error">
      {{ checksOff.length }} server(s) have AdGuard's own update check switched off, so they will
      never report a new release: {{ checksOff.map((s) => s.name).join(', ') }}. Turn on
      <strong>Automatically check for updates</strong> in each one's AdGuard Home settings
      (Settings → General settings).
    </div>

    <div v-if="!data.enabled" class="alert alert-error">
      Automatic updates are switched off for the whole app (<span class="mono">AUTO_UPDATE_ENABLED=false</span>).
      You can still update servers by hand from this page.
    </div>

    <div class="card" style="margin-bottom:24px">
      <div class="card-header">
        <h2>Schedule</h2>
        <span class="muted">last run: {{ fmt(data.last_run) }}</span>
      </div>
      <div style="padding:16px">
        <p style="margin-top:0">
          Eligible servers are checked every
          <strong>{{ Math.round(data.interval_seconds / 60) }} min</strong>
          <template v-if="data.window">
            and upgraded only between <strong>{{ data.window }} UTC</strong>
            (<span :class="data.in_window ? 'badge synced' : 'badge offline'">
              {{ data.in_window ? 'in window now' : 'outside the window now' }}
            </span>).
          </template>
          <template v-else>, at <strong>any time of day</strong>.</template>
          A failed attempt is retried after {{ data.retry_hours }}h.
        </p>
        <div class="hint">
          Upgrading restarts AdGuard Home, which briefly stops DNS resolution on that server.
          Set <span class="mono">AUTO_UPDATE_WINDOW</span> to confine it to a maintenance window,
          and keep at least one server per zone on a different schedule.
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:24px">
      <div class="card-header"><h2>Servers</h2></div>
      <table>
        <thead><tr>
          <th>Server</th><th>Zone</th><th>Installed</th><th>Current</th><th>Available</th>
          <th>Auto-update</th><th>Last attempt</th><th></th>
        </tr></thead>
        <tbody>
          <tr v-for="s in servers" :key="s.id">
            <td>
              <strong>{{ s.name }}</strong>
              <span v-if="!s.enabled" class="badge offline" style="margin-left:6px">disabled</span>
              <div v-if="s.update_error" class="hint" style="color:var(--red)">{{ s.update_error }}</div>
              <div v-else-if="s.skip_reason && s.auto_update" class="hint">{{ s.skip_reason }}</div>
            </td>
            <td><ZoneBadge :id="s.zone_id" :label="zoneName(s.zone_id)" /></td>
            <td>
              <span v-if="s.install_method" class="badge global">
                {{ s.install_method === 'docker' ? 'Docker' : 'Bare-metal' }}
              </span>
              <span v-else class="muted">unknown</span>
            </td>
            <td class="mono">{{ s.version || '—' }}</td>
            <td>
              <span v-if="s.update_available" class="badge drift">↑ {{ s.latest_version }}</span>
              <span v-else-if="s.update_check_disabled" class="badge offline"
                    title="AdGuard Home → Settings → General settings → Automatically check for updates">
                checks disabled
              </span>
              <span v-else class="muted">up to date</span>
            </td>
            <td>
              <label class="checkbox-row" style="margin:0">
                <input type="checkbox" :checked="s.auto_update" :disabled="!auth.isEditor"
                       @change="toggleAuto(s)" />
              </label>
            </td>
            <td class="muted">
              <span v-if="stateBadge(s)" class="badge" :class="stateBadge(s).cls">{{ stateBadge(s).text }}</span>
              <div class="hint">{{ fmt(s.update_attempted_at) }}</div>
            </td>
            <td class="row-actions">
              <button v-if="auth.isEditor" class="btn btn-sm"
                      :disabled="!s.update_available || busy === s.id"
                      @click="runOne(s)">
                <span v-if="busy === s.id" class="spinner"></span><span>Update now</span>
              </button>
            </td>
          </tr>
          <tr v-if="!servers.length"><td colspan="8" class="empty">No servers yet.</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-header"><h2>Docker servers</h2></div>
      <div style="padding:16px">
        <p style="margin-top:0">
          A container cannot replace the image it is running from, so AdGuard Home in Docker
          reports that it cannot update itself and this app will not try. Run the on-box
          updater on those hosts instead — it pulls the image and recreates the container
          (keeping its volumes, ports and settings) on a daily timer.
        </p>
        <pre class="mono" style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;overflow-x:auto;font-size:13px;white-space:pre-wrap;word-break:break-all">{{ data.docker_agent_command }}</pre>
        <button class="btn btn-sm" style="margin-top:10px" @click="copyCommand">
          {{ copied ? 'Copied!' : 'Copy command' }}
        </button>
        <div class="hint" style="margin-top:12px">
          Servers provisioned with <strong>auto-update</strong> already have it.
          Pass <span class="mono">CONTAINER=&lt;name&gt;</span> if the container isn't called
          <span class="mono">adguardhome</span>, or <span class="mono">UNINSTALL=true</span> to remove it.
        </div>
        <div v-if="delegated.length" class="hint" style="margin-top:12px">
          Needs it on: {{ delegated.map((s) => s.name).join(', ') }}.
        </div>
      </div>
    </div>
  </div>

  <div class="content" v-else><div class="card"><div class="empty">Loading…</div></div></div>
</template>
