<template>
  <v-dialog :model-value="modelValue" max-width="640" persistent @update:model-value="emit('update:modelValue', $event)">
    <v-card>
      <v-card-title class="d-flex align-center" style="gap: 0.5rem;">
        <span>{{ title }}</span>
      </v-card-title>
      <v-card-text>
        <div v-if="roots.length" class="d-flex align-center flex-wrap mb-2" style="gap: 0.4rem;">
          <span class="text-caption text-medium-emphasis me-1">Drives:</span>
          <v-chip
            v-for="r in roots"
            :key="r.path"
            size="small"
            link
            :variant="path.startsWith(r.path) ? 'flat' : 'outlined'"
            :color="path.startsWith(r.path) ? 'primary' : undefined"
            @click="navigate(r.path)"
          >
            {{ r.path }}<span v-if="r.entry_count === 0" class="text-medium-emphasis ms-1">(empty)</span>
          </v-chip>
        </div>

        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <v-btn size="small" variant="text" prepend-icon="mdi-arrow-up" :disabled="!parent" @click="navigate(parent!)">Up</v-btn>
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
        <v-btn
          v-if="selectDir"
          color="primary"
          variant="tonal"
          prepend-icon="mdi-folder-check"
          @click="pickCurrentDir"
        >Select this folder</v-btn>
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

interface RootInfo {
  path: string
  exists: boolean
  entry_count: number
}

const props = defineProps<{
  modelValue: boolean
  title: string
  initialPath?: string | null
  /** When true, show a "Select this folder" action that picks the current
   *  directory instead of a file (used by the DRep key generator). */
  selectDir?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  pick: [path: string]
}>()

function pickCurrentDir() {
  emit('pick', path.value)
  emit('update:modelValue', false)
}

const path = ref('')
const parent = ref<string | null>(null)
const entries = ref<DirEntry[]>([])
const roots = ref<RootInfo[]>([])
const loading = ref(false)
const loadError = ref<string | null>(null)

async function loadRoots(): Promise<RootInfo[]> {
  try {
    const r = await fetch('/api/list-dir-roots')
    if (!r.ok) throw new Error(await r.text())
    const all: RootInfo[] = await r.json()
    roots.value = all.filter((x) => x.exists)
  } catch {
    roots.value = []
  }
  return roots.value
}

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
  async (open) => {
    if (!open) return
    const available = await loadRoots()
    if (props.initialPath) {
      navigate(props.initialPath.replace(/\/[^/]*$/, ''))
      return
    }
    // Open on the first populated root instead of a bare, empty /media:
    // USB drives mount under /run/media/<user> (or /media/<user>) here.
    const target = available.find((r) => r.entry_count > 0) ?? available[0]
    navigate(target ? target.path : '')
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
  background: rgba(var(--drep-gold-rgb), 0.08);
}
.entry-dir .entry-name { color: var(--drep-gold); }
.entry-file .entry-name { color: rgba(255, 255, 255, 0.85); }
.entry-hidden { opacity: 0.55; }
</style>
