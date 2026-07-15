<template>
  <div class="mb-4">
    <div class="d-flex align-start" style="gap: 0.5rem;">
      <v-text-field
        :model-value="modelValue ?? ''"
        :label="label"
        :readonly="readonly"
        :placeholder="isFocused ? '' : `/secure/${kind}.skey`"
        :persistent-hint="true"
        :hint="`Powers: ${powers}`"
        variant="outlined"
        density="compact"
        :hide-details="false"
        @update:model-value="(v) => emit('update:modelValue', (v as string) || null)"
        @focus="isFocused = true"
        @blur="isFocused = false; emit('test')"
      >
        <template #append-inner>
          <span :class="['ki-bulb', bulbClass]" :title="bulbTitle" />
        </template>
      </v-text-field>
      <v-btn
        size="small"
        variant="outlined"
        prepend-icon="mdi-folder-open"
        :disabled="readonly"
        class="mt-1"
        @click="browseOpen = true"
      >Browse</v-btn>
    </div>
    <div v-if="status.status === 'wrong_role'" class="text-caption text-warn mt-1 ml-3">
      Wrong role: this file is not a {{ powers }}.
    </div>
    <div v-else-if="status.status === 'error'" class="text-caption text-bad mt-1 ml-3">
      {{ status.message }}
    </div>

    <FileBrowserDialog
      v-model="browseOpen"
      :title="`Select ${label}`"
      :initial-path="modelValue"
      @pick="onPick"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import FileBrowserDialog from './FileBrowserDialog.vue'

interface ValidationResult {
  status: 'missing' | 'valid' | 'wrong_role' | 'error'
  message?: string
}

const props = defineProps<{
  modelValue: string | null
  label: string
  powers: string
  kind: 'drep' | 'payment'
  readonly?: boolean
  status: ValidationResult
}>()

const emit = defineEmits<{
  'update:modelValue': [value: string | null]
  test: []
}>()

const browseOpen = ref(false)
const isFocused = ref(false)

function onPick(picked: string) {
  emit('update:modelValue', picked)
  emit('test')
}

const bulbClass = computed(() => {
  switch (props.status.status) {
    case 'valid': return 'ok'
    case 'wrong_role': return 'warn'
    case 'error': return 'bad'
    default: return 'idle'
  }
})

const bulbTitle = computed(() => {
  switch (props.status.status) {
    case 'valid': return 'Valid — parsed and matches expected role'
    case 'wrong_role': return `Wrong role: this file is not a ${props.powers}`
    case 'error': return props.status.message || 'Validation failed'
    default: return 'Not yet validated'
  }
})
</script>

<style scoped>
.ki-bulb {
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  margin-left: 0.25rem;
}
.ki-bulb.ok { background: #4CAF50; box-shadow: 0 0 6px rgba(76,175,80,0.6); }
.ki-bulb.warn { background: #FFB74D; box-shadow: 0 0 6px rgba(255,183,77,0.6); }
.ki-bulb.bad { background: #FF6B6B; box-shadow: 0 0 6px rgba(255,107,107,0.6); }
.ki-bulb.idle { background: rgba(255,255,255,0.18); }
.text-warn { color: #FFB74D; }
.text-bad { color: #FF6B6B; }
</style>
