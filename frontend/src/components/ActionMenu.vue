<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const open = ref(false)
const root = ref(null)
const menuStyle = ref({})

function toggle() {
  open.value = !open.value
  if (open.value && root.value) {
    // Fixed positioning so the menu escapes scrollable/overflow containers.
    const r = root.value.getBoundingClientRect()
    menuStyle.value = { position: 'fixed', top: `${r.bottom + 4}px`, right: `${window.innerWidth - r.right}px` }
  }
}
function close() { open.value = false }
function onDocClick(e) {
  if (root.value && !root.value.contains(e.target)) open.value = false
}
function onScroll() { if (open.value) open.value = false }

onMounted(() => {
  document.addEventListener('click', onDocClick)
  window.addEventListener('scroll', onScroll, true)
  window.addEventListener('resize', onScroll)
})
onUnmounted(() => {
  document.removeEventListener('click', onDocClick)
  window.removeEventListener('scroll', onScroll, true)
  window.removeEventListener('resize', onScroll)
})
</script>

<template>
  <div class="action-menu" ref="root">
    <button class="btn btn-sm btn-icon" :aria-expanded="open" title="Actions" @click.stop="toggle">⋯</button>
    <!-- close after an item's own handler runs (events bubble up to here) -->
    <div v-if="open" class="menu" :style="menuStyle" @click="close">
      <slot />
    </div>
  </div>
</template>
