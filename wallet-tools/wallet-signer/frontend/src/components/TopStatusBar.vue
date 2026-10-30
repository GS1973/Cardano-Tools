<template>
  <header class="drep-topbar">
    <div class="brand">
      <v-icon icon="mdi-key-variant" size="20" class="brand-icon" />
      <span class="brand-name">Wallet&nbsp;Tools</span>
      <span class="brand-sub">signer</span>
    </div>
    <div class="status-item ml-4" :title="networkTitle">
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
    <v-spacer />
    <span v-if="epoch != null" class="status-item" title="Last-seen epoch from a received request">
      <span class="status-label">Epoch</span>{{ epoch }}
    </span>
    <span class="version">{{ VERSION }}</span>
  </header>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { SIGNER_STATUS_POLL_INTERVAL_MS } from '@wallet-tools/shared-frontend/constants/timings'

const VERSION = `v${__APP_VERSION__}`
// Tri-state: null = never measured / measurement stale. The badge must not
// claim "No network detected" unless a successful /api/status response said so.
const airGapped = ref<boolean | null>(null)
const epoch = ref<number | null>(null)
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
    epoch.value = d.chain_context?.current_epoch ?? null
  } catch {
    // Fail closed: without a successful measurement (or after repeated
    // failures) show the explicit "unverified" state instead of a stale
    // green badge.
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
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.drep-topbar {
  position: fixed;
  top: 0; left: 0; right: 0;
  height: 56px;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0 24px;
  background: #16161f;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  z-index: 1005;
}
.brand { display: flex; align-items: baseline; gap: 0.4rem; }
.brand-icon { color: var(--wallet-gold, #FFD700); align-self: center; }
.brand-name { font-weight: 600; letter-spacing: 0.02em; color: #fff; }
.brand-sub { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: rgba(255,255,255,0.4); }
.status-item { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8125rem; }
.status-label { color: rgba(255,255,255,0.55); text-transform: uppercase; letter-spacing: 0.04em; margin-right: 0.3rem; }
.version { font-size: 0.8125rem; color: rgba(255,255,255,0.45); }
.airgap-ok { color: #4CAF50; font-weight: 700; letter-spacing: 0.02em; }
.airgap-bad { color: #FF6B6B; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
.airgap-unknown { color: #FFB74D; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
.blink { animation: blink-warn 1.1s ease-in-out infinite; }
@keyframes blink-warn { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
</style>
