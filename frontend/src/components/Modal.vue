<script setup>
defineProps({ title: String })
const emit = defineEmits(['close'])
</script>

<template>
  <div class="modal-overlay" @click.self="emit('close')">
    <div class="modal">
      <div class="modal-header">{{ title }}</div>
      <div class="modal-body"><slot /></div>
      <div class="modal-footer"><slot name="footer" /></div>
    </div>
  </div>
</template>
