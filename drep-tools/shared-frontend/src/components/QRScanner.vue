<template>
  <div>
    <div :id="readerId" class="qr-reader-frame"></div>

    <div v-if="active" class="d-flex align-center mt-2" style="gap: 0.75rem;">
      <v-progress-linear
        :model-value="progressPercent"
        :indeterminate="totalFragments === null"
        color="primary"
        height="8"
        rounded
        style="flex: 1;"
      />
      <span class="text-caption text-medium-emphasis" style="min-width: 5rem;">
        {{ collectedCount }} / {{ totalFragments ?? '?' }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { Html5Qrcode } from 'html5-qrcode'

const emit = defineEmits<{
  complete: [fragments: string[]]
  error: [msg: string]
}>()

// html5-qrcode's constructor only accepts an element id, so give every
// instance its own: two scanners mounted at once (inline panel plus the
// enlarge dialog) must not both bind to a single page-global id.
const readerId = `qr-reader-${Math.random().toString(36).slice(2)}`
const active = ref(false)
const totalFragments = ref<number | null>(null)
const fragmentsByIndex = ref<Map<number, string>>(new Map())

let scanner: Html5Qrcode | null = null

const collectedCount = computed(() => fragmentsByIndex.value.size)
const progressPercent = computed(() => {
  if (totalFragments.value === null) return 0
  return Math.round((collectedCount.value / totalFragments.value) * 100)
})

function parseHeader(text: string): { index: number; total: number } | null {
  const m = text.match(/^ur:[^/]+\/(\d+)-(\d+)\//i)
  if (!m) return null
  const index = parseInt(m[1], 10)
  const total = parseInt(m[2], 10)
  if (!Number.isFinite(index) || !Number.isFinite(total) || index < 1 || total < 1 || index > total) {
    return null
  }
  return { index, total }
}

function onDecode(text: string) {
  const hdr = parseHeader(text)
  if (!hdr) return
  if (totalFragments.value === null) totalFragments.value = hdr.total
  if (totalFragments.value !== hdr.total) {
    fragmentsByIndex.value.clear()
    totalFragments.value = hdr.total
  }
  if (!fragmentsByIndex.value.has(hdr.index)) {
    fragmentsByIndex.value.set(hdr.index, text)
    fragmentsByIndex.value = new Map(fragmentsByIndex.value)
  }
  if (fragmentsByIndex.value.size === totalFragments.value) {
    finishCollection()
  }
}

function finishCollection() {
  const ordered: string[] = []
  for (let i = 1; i <= (totalFragments.value ?? 0); i++) {
    const f = fragmentsByIndex.value.get(i)
    if (!f) {
      // A hole means header validation was bypassed somehow; restart the
      // collection rather than emit an incomplete set as complete.
      totalFragments.value = null
      fragmentsByIndex.value = new Map()
      return
    }
    ordered.push(f)
  }
  stopScanner()
  emit('complete', ordered)
}

/**
 * Translate raw getUserMedia / html5-qrcode errors into something the operator
 * can act on. Matches both DOMException-style names and the substring forms
 * html5-qrcode tends to surface as plain strings.
 */
function friendlyError(e: unknown): string {
  const raw = (e instanceof Error ? e.message : String(e)).toLowerCase()
  if (raw.includes('notallowederror') || raw.includes('permission denied')) {
    return 'Camera permission denied: allow camera access in your browser.'
  }
  if (
    raw.includes('notfounderror') ||
    raw.includes('requested device not found') ||
    raw.includes('no camera') ||
    raw.includes('cameras to use') ||
    raw.includes('cannot find devices')
  ) {
    return 'No camera detected on this machine. Plug one in or use the paste field.'
  }
  if (raw.includes('notreadableerror') || raw.includes('could not start video source')) {
    return 'Camera is in use by another application.'
  }
  if (raw.includes('overconstrainederror')) {
    return 'No suitable camera found.'
  }
  if (raw.includes('mediadevices') || raw.includes('getusermedia')) {
    return 'This browser does not allow camera access on this origin (HTTPS or localhost required).'
  }
  return e instanceof Error ? e.message : String(e)
}

async function startScanner() {
  totalFragments.value = null
  fragmentsByIndex.value = new Map()
  try {
    // Probe for camera availability before constructing the scanner so a
    // missing-camera situation gives a clean "no camera" message instead
    // of getting wrapped inside html5-qrcode's start() error.
    const cameras = await Html5Qrcode.getCameras().catch(() => [] as Array<{ id: string }>)
    if (!cameras || cameras.length === 0) {
      const msg = 'No camera detected on this machine. Plug one in or use the paste field.'
      emit('error', msg)
      return
    }

    scanner = new Html5Qrcode(readerId)
    await scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 280, height: 280 } },
      onDecode,
      () => { /* per-frame no-detect, ignore */ },
    )
    active.value = true
  } catch (e: unknown) {
    const msg = friendlyError(e)
    emit('error', msg)
  }
}

async function retry() {
  await startScanner()
}

async function stopScanner() {
  active.value = false
  if (scanner) {
    try {
      await scanner.stop()
      await scanner.clear()
    } catch { /* already stopped */ }
    scanner = null
  }
}

onMounted(() => startScanner())
onUnmounted(() => stopScanner())

defineExpose({ stopScanner, retry })
</script>

<style scoped>
.qr-reader-frame {
  width: 100%;
  max-width: 480px;
  aspect-ratio: 1;
  background: #000;
  border-radius: 8px;
  overflow: hidden;
}
.text-bad {
  color: #FF6B6B;
}
</style>
