<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const open = ref(false)
const root = ref(null)

function toggle() { open.value = !open.value }
function close() { open.value = false }
function onDocClick(e) {
  if (root.value && !root.value.contains(e.target)) open.value = false
}

onMounted(() => document.addEventListener('click', onDocClick))
onUnmounted(() => document.removeEventListener('click', onDocClick))
</script>

<template>
  <div class="action-menu" ref="root">
    <button class="btn btn-sm btn-icon" :aria-expanded="open" title="Actions" @click.stop="toggle">⋯</button>
    <!-- close after an item's own handler runs (events bubble up to here) -->
    <div v-if="open" class="menu" @click="close">
      <slot />
    </div>
  </div>
</template>
