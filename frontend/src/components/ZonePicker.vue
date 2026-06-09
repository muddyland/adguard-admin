<script setup>
const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  zones: { type: Array, default: () => [] },
})
const emit = defineEmits(['update:modelValue'])

function toggle(id) {
  const set = new Set(props.modelValue)
  set.has(id) ? set.delete(id) : set.add(id)
  emit('update:modelValue', [...set])
}
function allOn() { emit('update:modelValue', props.zones.map((z) => z.id)) }
function clear() { emit('update:modelValue', []) }
</script>

<template>
  <div>
    <div class="zone-picker">
      <label v-for="z in zones" :key="z.id" class="zone-opt">
        <input type="checkbox" :checked="modelValue.includes(z.id)" @change="toggle(z.id)" />
        <span>{{ z.name }}</span>
      </label>
      <div v-if="!zones.length" class="hint" style="padding:6px">No zones yet — create one first.</div>
    </div>
    <div v-if="zones.length" class="zone-picker-actions">
      <a href="#" @click.prevent="allOn">Select all</a>
      <a href="#" @click.prevent="clear">Clear</a>
    </div>
  </div>
</template>
