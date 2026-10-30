<template>
  <SharedTopStatusBar
    :version="VERSION"
    :epoch="epoch"
    :epoch-ends-unix="epochEndsUnix"
    :kes-period="kesPeriod"
    :opcert-expires-unix="opcertExpiresUnix"
  >
    <template #first-status>
      <div class="status-item" :title="koiosTitle">
        <span class="status-label">Koios</span>
        <span :class="['koios-bulb', koiosOk ? 'ok' : 'bad']" />
      </div>
    </template>
  </SharedTopStatusBar>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import SharedTopStatusBar from '@spo-tools/shared-frontend/components/TopStatusBar.vue'
import { ONLINE_STATUS_POLL_INTERVAL_MS } from '@spo-tools/shared-frontend/constants/timings'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'

const VERSION = `v${__APP_VERSION__}`

const epoch = ref<number | null>(null)
const kesPeriod = ref<number | null>(null)
const epochEndsUnix = ref<number | null>(null)
const opcertExpiresUnix = ref<number | null>(null)
const koiosOk = ref(false)
const koiosTitle = ref('Connecting…')

let pollTimer: ReturnType<typeof setInterval> | null = null
let backoffUntil = 0

async function refresh() {
  if (Date.now() < backoffUntil) return
  try {
    const r = await fetch('/api/kes/status')
    if (!r.ok) {
      koiosOk.value = false
      epoch.value = null
      kesPeriod.value = null
      epochEndsUnix.value = null
      opcertExpiresUnix.value = null
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') {
        koiosTitle.value = 'Pool not configured: go to Setup'
      } else if (err.code === 'upstream_unavailable') {
        koiosTitle.value = 'Koios rate-limited (paused 5 min)'
        backoffUntil = Date.now() + 5 * 60_000
      } else if (err.code === 'snapshot_not_ready') {
        koiosTitle.value = 'Koios unreachable'
      } else {
        koiosTitle.value = err.message || `HTTP ${r.status}`
      }
      return
    }
    const d = await r.json()
    epoch.value = d.current_epoch
    kesPeriod.value = d.current_kes_period
    epochEndsUnix.value = d.epoch_ends_at_unix
    opcertExpiresUnix.value = d.opcert_expires_at_unix
    koiosOk.value = true
    koiosTitle.value = 'Koios reachable'
  } catch (e: unknown) {
    koiosOk.value = false
    koiosTitle.value = e instanceof Error ? e.message : 'Network error'
  }
}

function onConfigSaved() {
  backoffUntil = 0
  refresh()
}

onMounted(() => {
  refresh()
  pollTimer = setInterval(refresh, ONLINE_STATUS_POLL_INTERVAL_MS)
  window.addEventListener('spo-config-saved', onConfigSaved)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
  window.removeEventListener('spo-config-saved', onConfigSaved)
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
.koios-bulb {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}
.koios-bulb.ok { background: #4CAF50; box-shadow: 0 0 6px rgba(76,175,80,0.7); }
.koios-bulb.bad { background: #FF6B6B; box-shadow: 0 0 6px rgba(255,107,107,0.7); }
</style>
