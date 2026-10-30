<template>
  <SharedTopStatusBar
    :version="VERSION"
    version-suffix="signer"
    :epoch="epoch"
    :epoch-ends-unix="epochEndsUnix"
    :kes-period="kesPeriod"
    :opcert-expires-unix="opcertExpiresUnix"
  >
    <template #first-status>
      <div class="status-item" :title="networkTitle">
        <template v-if="airGapped === true">
          <v-icon size="14" color="success">mdi-check-circle</v-icon>
          <span class="airgap-ok">No network detected</span>
        </template>
        <template v-else-if="airGapped === false">
          <v-icon size="14" color="error" class="blink">mdi-alert</v-icon>
          <span class="airgap-bad blink">NETWORK DETECTED!</span>
        </template>
        <template v-else>
          <v-icon size="14" color="warning" class="blink">mdi-help-circle</v-icon>
          <span class="airgap-unknown blink">NETWORK CHECK UNVERIFIED</span>
        </template>
      </div>
    </template>
  </SharedTopStatusBar>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import SharedTopStatusBar from '@spo-tools/shared-frontend/components/TopStatusBar.vue'
import { SIGNER_STATUS_POLL_INTERVAL_MS } from '@spo-tools/shared-frontend/constants/timings'

const VERSION = `v${__APP_VERSION__}`

const epoch = ref<number | null>(null)
const kesPeriod = ref<number | null>(null)
const epochEndsUnix = ref<number | null>(null)
const opcertExpiresUnix = ref<number | null>(null)
// Tri-state: null = never measured / measurement stale. The badge must not
// claim "No network detected" unless a successful /api/status response said so.
const airGapped = ref<boolean | null>(null)
const networkTitle = ref('Network check not run yet')

let pollTimer: ReturnType<typeof setInterval> | null = null
// Tolerate this many consecutive failed polls before degrading a previously
// measured state back to "unverified".
const MAX_FAILED_POLLS = 3
let failedPolls = 0

async function refresh() {
  try {
    const r = await fetch('/api/status')
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    const d = await r.json()
    failedPolls = 0
    airGapped.value = d.air_gapped ?? null
    networkTitle.value = d.air_gapped === true
      ? 'No active non-loopback network adapter detected. This check sees IP traffic only. It cannot confirm an air gap.'
      : d.air_gapped === false
        ? 'WARNING: this signer machine is connected to a network'
        : 'Network check not run yet'
    const ctx = d.chain_context ?? null
    epoch.value = ctx?.current_epoch ?? null
    kesPeriod.value = ctx?.current_kes_period ?? null
    epochEndsUnix.value = ctx?.epoch_ends_at_unix ?? null
    opcertExpiresUnix.value = ctx?.opcert_expires_at_unix ?? null
  } catch {
    // Fail closed: without a successful measurement (or after repeated
    // failures) show the explicit "unverified" state instead of a stale
    // green badge. Chain-context values keep their last-known reading.
    failedPolls += 1
    if (airGapped.value === null || failedPolls >= MAX_FAILED_POLLS) {
      airGapped.value = null
      networkTitle.value = 'Network check unknown: the signer backend is not responding'
    }
  }
}

onMounted(() => {
  refresh()
  pollTimer = setInterval(refresh, SIGNER_STATUS_POLL_INTERVAL_MS)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style scoped>
.status-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.8125rem;
}
.airgap-ok {
  color: #4CAF50;
  font-weight: 700;
  letter-spacing: 0.02em;
}
.airgap-bad {
  color: #FF6B6B;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.airgap-unknown {
  color: #FFB74D;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.blink {
  animation: blink-warn 1.1s ease-in-out infinite;
}
@keyframes blink-warn {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}
</style>
