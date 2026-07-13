<template>
  <v-dialog :model-value="modelValue" max-width="640" persistent @update:model-value="emit('update:modelValue', $event)">
    <v-card>
      <v-card-title class="d-flex align-center" style="gap: 0.5rem;">
        <span>{{ title }}</span>
      </v-card-title>
      <v-card-text>
        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <v-btn
            size="small"
            variant="text"
            prepend-icon="mdi-arrow-up"
            :disabled="!parent"
            @click="navigate(parent!)"
          >Up</v-btn>
          <code class="path-display">{{ path }}</code>
          <v-spacer />
          <v-btn size="small" variant="text" prepend-icon="mdi-refresh" @click="navigate(path)">Refresh</v-btn>
        </div>

        <v-alert v-if="loadError" type="error" density="compact" variant="tonal" class="mb-2">{{ loadError }}</v-alert>

        <div class="entry-list">
          <div
            v-for="e in entries"
            :key="e.name"
            class="entry-row"
            :class="{ 'entry-dir': e.is_dir, 'entry-file': e.is_file, 'entry-hidden': e.name.startsWith('.') }"
            @click="select(e)"
          >
            <v-icon size="18" class="me-2">{{ e.is_dir ? 'mdi-folder' : 'mdi-file-outline' }}</v-icon>
            <span class="entry-name">{{ e.name }}</span>
          </div>
          <div v-if="!loading && entries.length === 0" class="text-medium-emphasis text-caption pa-3">
            (empty directory)
          </div>
        </div>
      </v-card-text>

      <v-card-actions class="pa-4">
        <v-spacer />
        <v-btn variant="text" @click="emit('update:modelValue', false)">Cancel</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

interface DirEntry {
  name: string
  is_dir: boolean
  is_file: boolean
}

const props = defineProps<{
  modelValue: boolean
  title: string
  initialPath?: string | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  pick: [path: string]
}>()

const path = ref('')
const parent = ref<string | null>(null)
const entries = ref<DirEntry[]>([])
const loading = ref(false)
const loadError = ref<string | null>(null)

async function navigate(target: string) {
  loading.value = true
  loadError.value = null
  try {
    const url = '/api/list-dir' + (target ? `?path=${encodeURIComponent(target)}` : '')
    const r = await fetch(url)
    if (!r.ok) throw new Error(await r.text())
    const d = await r.json()
    path.value = d.path
    parent.value = d.parent
    entries.value = d.entries
  } catch (e: unknown) {
    loadError.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

function select(e: DirEntry) {
  if (e.is_dir) {
    navigate(`${path.value}/${e.name}`)
  } else if (e.is_file) {
    emit('pick', `${path.value}/${e.name}`)
    emit('update:modelValue', false)
  }
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      const start = props.initialPath
        ? props.initialPath.replace(/\/[^/]*$/, '') // parent of file path if given
        : ''
      navigate(start)
    }
  },
)
</script>

<style scoped>
.path-display {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.55);
  word-break: break-all;
}
.entry-list {
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.25);
  max-height: 360px;
  overflow-y: auto;
}
.entry-row {
  display: flex;
  align-items: center;
  padding: 0.35rem 0.6rem;
  cursor: pointer;
  font-size: 0.875rem;
}
.entry-row:hover {
  background: rgba(var(--spo-gold-rgb), 0.08);
}
.entry-dir .entry-name { color: var(--spo-gold); }
.entry-file .entry-name { color: rgba(255, 255, 255, 0.85); }
.entry-hidden {
  opacity: 0.55;
}
</style>
