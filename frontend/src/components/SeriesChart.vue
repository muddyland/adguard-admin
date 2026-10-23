<script setup>
// A small time-series chart drawn as SVG: thin lines, a wash under the first
// series, recessive hairline grid, crosshair + one tooltip for every series,
// and a table view so no value is reachable only by hover.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

const props = defineProps({
  points: { type: Array, default: () => [] },           // [{ ts, <key>: number|null, ... }]
  series: { type: Array, required: true },               // [{ key, label, color }]
  height: { type: Number, default: 220 },
  unit: { type: String, default: '' },
  rangeSeconds: { type: Number, default: 86400 },
})

const wrap = ref(null)
const width = ref(640)
const hoverIndex = ref(null)
const showTable = ref(false)
let observer = null

onMounted(() => {
  if (wrap.value) {
    width.value = wrap.value.clientWidth || 640
    observer = new ResizeObserver((entries) => {
      for (const e of entries) width.value = Math.max(240, e.contentRect.width)
    })
    observer.observe(wrap.value)
  }
})
onBeforeUnmount(() => observer && observer.disconnect())

const M = { top: 12, right: 14, bottom: 26, left: 46 }
const plotW = computed(() => Math.max(10, width.value - M.left - M.right))
const plotH = computed(() => props.height - M.top - M.bottom)

const hasData = computed(() => props.points.some((p) => props.series.some((s) => p[s.key] != null)))

function niceMax(v) {
  if (!(v > 0)) return 1
  const exp = Math.pow(10, Math.floor(Math.log10(v)))
  const f = v / exp
  const step = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((c) => f <= c) || 10
  return step * exp
}
const yMax = computed(() => {
  let m = 0
  for (const p of props.points) for (const s of props.series) if (p[s.key] != null) m = Math.max(m, Number(p[s.key]))
  return niceMax(m * 1.05)
})
const yTicks = computed(() => [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax.value))

function x(i) { return M.left + (props.points.length > 1 ? (i / (props.points.length - 1)) * plotW.value : plotW.value / 2) }
function y(v) { return M.top + plotH.value - (Number(v) / yMax.value) * plotH.value }

function path(key) {
  let d = ''
  let open = false
  props.points.forEach((p, i) => {
    if (p[key] == null) { open = false; return }
    d += `${open ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`
    open = true
  })
  return d
}
function area(key) {
  // One closed shape per contiguous run, so gaps stay gaps.
  const base = M.top + plotH.value
  let out = ''
  let run = []
  const flush = () => {
    if (run.length < 2) { run = []; return }
    out += `M${x(run[0]).toFixed(1)},${base.toFixed(1)}`
    for (const i of run) out += `L${x(i).toFixed(1)},${y(props.points[i][key]).toFixed(1)}`
    out += `L${x(run[run.length - 1]).toFixed(1)},${base.toFixed(1)}Z`
    run = []
  }
  props.points.forEach((p, i) => { if (p[key] == null) flush(); else run.push(i) })
  flush()
  return out
}

function compact(v) {
  if (v == null) return '—'
  const n = Number(v)
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M'
  if (Math.abs(n) >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K'
  return n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1).replace(/\.0$/, '') : n.toFixed(2).replace(/\.?0+$/, '')
}
function timeLabel(ts, long = false) {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ''
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  if (props.rangeSeconds > 48 * 3600 || long) {
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + (long || props.rangeSeconds <= 7 * 86400 ? ' ' + time : '')
  }
  return time
}
const xTicks = computed(() => {
  const n = props.points.length
  if (!n) return []
  const count = Math.min(6, Math.max(2, Math.floor(plotW.value / 110)))
  const out = []
  for (let k = 0; k < count; k++) {
    const i = Math.round((k / (count - 1)) * (n - 1))
    out.push({ i, label: timeLabel(props.points[i].ts) })
  }
  return out
})

function onMove(evt) {
  if (!props.points.length) return
  const rect = evt.currentTarget.getBoundingClientRect()
  const px = evt.clientX - rect.left - M.left
  const i = Math.round((px / plotW.value) * (props.points.length - 1))
  hoverIndex.value = Math.max(0, Math.min(props.points.length - 1, i))
}
function onLeave() { hoverIndex.value = null }
const hover = computed(() => (hoverIndex.value == null ? null : props.points[hoverIndex.value]))
const tooltipStyle = computed(() => {
  if (hoverIndex.value == null) return {}
  const px = x(hoverIndex.value)
  const flip = px > width.value * 0.6
  return { left: `${flip ? px - 12 : px + 12}px`, transform: flip ? 'translateX(-100%)' : 'none', top: `${M.top}px` }
})
</script>

<template>
  <div class="chart" ref="wrap">
    <div class="chart-head">
      <div class="chart-legend" aria-label="Series">
        <span v-for="s in series" :key="s.key" class="chart-key">
          <span class="chart-swatch" :style="{ background: s.color }"></span>{{ s.label }}
        </span>
      </div>
      <button class="btn btn-sm" type="button" @click="showTable = !showTable">{{ showTable ? 'Chart' : 'Table' }}</button>
    </div>

    <div v-if="!hasData" class="empty" :style="{ height: height + 'px', display: 'flex', alignItems: 'center', justifyContent: 'center' }">
      <slot name="empty">No samples yet. One is stored per reconcile cycle.</slot>
    </div>

    <div v-else-if="showTable" class="chart-table">
      <table>
        <thead><tr><th>Time</th><th v-for="s in series" :key="s.key" style="text-align:right">{{ s.label }}</th></tr></thead>
        <tbody>
          <tr v-for="p in points.filter((q) => series.some((s) => q[s.key] != null))" :key="p.ts">
            <td class="muted">{{ timeLabel(p.ts, true) }}</td>
            <td v-for="s in series" :key="s.key" style="text-align:right">{{ compact(p[s.key]) }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-else class="chart-plot" :style="{ height: height + 'px' }">
      <svg :width="width" :height="height" @pointermove="onMove" @mousemove="onMove" @pointerleave="onLeave" @mouseleave="onLeave" role="img" aria-label="Time series">
        <g class="chart-grid">
          <line v-for="t in yTicks" :key="t" :x1="M.left" :x2="M.left + plotW" :y1="y(t)" :y2="y(t)" />
        </g>
        <g class="chart-axis">
          <text v-for="t in yTicks" :key="'y' + t" :x="M.left - 8" :y="y(t) + 4" text-anchor="end">{{ compact(t) }}</text>
          <text v-for="(t, k) in xTicks" :key="'x' + t.i" :x="x(t.i)" :y="height - 8" :text-anchor="k === 0 ? 'start' : k === xTicks.length - 1 ? 'end' : 'middle'">{{ t.label }}</text>
        </g>
        <path :d="area(series[0].key)" :fill="series[0].color" fill-opacity="0.1" stroke="none" />
        <path v-for="s in series" :key="s.key" :d="path(s.key)" :stroke="s.color" fill="none" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
        <template v-if="hover">
          <line class="chart-crosshair" :x1="x(hoverIndex)" :x2="x(hoverIndex)" :y1="M.top" :y2="M.top + plotH" />
          <template v-for="s in series" :key="'d' + s.key">
            <circle v-if="hover[s.key] != null" :cx="x(hoverIndex)" :cy="y(hover[s.key])" r="4.5" :fill="s.color" class="chart-dot" />
          </template>
        </template>
      </svg>
      <div v-if="hover" class="chart-tooltip" :style="tooltipStyle">
        <div class="muted">{{ timeLabel(hover.ts, true) }}</div>
        <div v-for="s in series" :key="s.key" class="chart-tip-row">
          <span class="chart-swatch" :style="{ background: s.color }"></span>
          <strong>{{ compact(hover[s.key]) }}</strong><span class="muted">{{ hover[s.key] == null ? '' : unit }} {{ s.label }}</span>
        </div>
        <div v-if="hover.reporting != null" class="muted" style="font-size:11px">{{ hover.reporting }} reporting</div>
      </div>
    </div>
  </div>
</template>
