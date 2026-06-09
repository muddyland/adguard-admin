<script setup>
import { zoneStyle } from '../zoneColor'

defineProps({
  id: { type: [Number, String], default: null },
  label: { type: String, required: true },
})
</script>

<template>
  <span class="badge" :class="{ offline: id == null }" :style="id != null ? zoneStyle(id) : null">{{ label }}</span>
</template>
