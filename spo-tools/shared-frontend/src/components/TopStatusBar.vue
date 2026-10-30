<template>
  <v-app-bar color="background" flat density="compact" class="border-b">
    <div class="d-flex align-center" style="width: 100%;">
      <div class="brand-cell">
        <span class="text-gold brand-mark">SPO Tools</span>
        <span class="text-medium-emphasis brand-version">
          <template v-if="versionSuffix">{{ versionSuffix }} · </template>{{ version }}
        </span>
      </div>
      <div class="d-flex align-center justify-center flex-grow-1 px-4" style="gap: 2rem;">
        <slot name="first-status" />
        <div class="status-item">
          <span class="status-label">Epoch</span>
          <span class="status-value">{{ epoch ?? 'n/a' }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">Epoch ends</span>
          <span class="status-value">{{ epochEnds }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">Current KES</span>
          <span class="status-value">{{ kesPeriod ?? 'n/a' }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">KES ends</span>
          <span class="status-value">{{ kesEnds }}</span>
        </div>
        <div
          class="status-item pairing-pill"
          :class="{ 'pairing-ok': paired === true, 'pairing-bad': paired === false }"
          role="button"
          tabindex="0"
          :title="paired === true ? `Paired (${pairingFingerprint})` : 'Not paired: click to pair'"
          @click="goToPairing"
          @keydown.enter="goToPairing"
        >
          <span class="status-label">Pairing</span>
          <span class="status-value">{{ pairingPillLabel }}</span>
        </div>
      </div>
    </div>
  </v-app-bar>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { COUNTDOWN_TICK_INTERVAL_MS, PAIRING_POLL_INTERVAL_MS } from '../constants/timings'

const props = defineProps<{
  version: string
  versionSuffix?: string
  epoch: number | null
  epochEndsUnix: number | null
  kesPeriod: number | null
  opcertExpiresUnix: number | null
}>()

const nowUnix = ref(Math.floor(Date.now() / 1000))

function fmtCountdown(target: number | null): string {
  if (target == null) return 'n/a'
  const remaining = target - nowUnix.value
  if (remaining <= 0) return 'expired'
  const days = Math.floor(remaining / 86400)
  const hours = Math.floor((remaining % 86400) / 3600)
  const mins = Math.floor((remaining % 3600) / 60)
  const secs = remaining % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${days}d ${pad(hours)}:${pad(mins)}:${pad(secs)}`
}

const epochEnds = computed(() => fmtCountdown(props.epochEndsUnix))
const kesEnds = computed(() => fmtCountdown(props.opcertExpiresUnix))

const paired = ref<boolean | null>(null)
const pairingFingerprint = ref<string | null>(null)
const pairingPillLabel = computed(() => {
  if (paired.value === null) return '…'
  return paired.value ? '✓' : '✕'
})
const router = useRouter()
function goToPairing() {
  router.push('/pairing')
}

async function refreshPairing() {
  try {
    const r = await fetch('/api/pairing/info')
    if (!r.ok) {
      paired.value = false
      pairingFingerprint.value = null
      return
    }
    const j = await r.json() as { paired: boolean; fingerprint: string | null }
    paired.value = j.paired
    pairingFingerprint.value = j.fingerprint
  } catch {
    paired.value = false
    pairingFingerprint.value = null
  }
}

let pairingPollTimer: ReturnType<typeof setInterval> | null = null
let tickTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  refreshPairing()
  pairingPollTimer = setInterval(refreshPairing, PAIRING_POLL_INTERVAL_MS)
  tickTimer = setInterval(() => { nowUnix.value = Math.floor(Date.now() / 1000) }, COUNTDOWN_TICK_INTERVAL_MS)
})

onUnmounted(() => {
  if (pairingPollTimer) clearInterval(pairingPollTimer)
  if (tickTimer) clearInterval(tickTimer)
})
</script>

<style scoped>
.status-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.8125rem;
}
.status-label {
  color: rgba(255, 255, 255, 0.55);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  font-weight: 400;
}
.status-value {
  color: var(--spo-gold);
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.brand-cell {
  width: 260px;
  padding-left: 1rem;
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  flex-shrink: 0;
}
.brand-mark {
  font-weight: 700;
  font-size: 1.1rem;
  letter-spacing: 0.05em;
}
.brand-version {
  font-size: 0.75rem;
}
.border-b { border-bottom: 1px solid rgba(255,255,255,0.08) !important; }
</style>
