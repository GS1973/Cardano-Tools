<template>
  <v-card class="mb-4">
    <v-card-title>Pool Information</v-card-title>
  </v-card>

  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />

  <v-card v-else>
    <v-card-text class="d-flex justify-end">
      <v-btn size="small" :loading="loading" prepend-icon="mdi-refresh" @click="load">Refresh</v-btn>
    </v-card-text>

    <v-card-text v-if="error">
      <v-alert type="error" density="compact" variant="tonal">{{ error }}</v-alert>
    </v-card-text>

    <v-card-text v-else-if="!info" class="text-medium-emphasis">
      Loading…
    </v-card-text>

    <v-card-text v-else>
      <v-alert
        v-if="info.pending"
        type="warning"
        density="comfortable"
        variant="tonal"
        class="mb-3"
      >
        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <strong>Pending pool-parameter change</strong>
          <v-spacer />
          <span class="text-caption text-medium-emphasis">
            Active in epoch {{ info.pending.active_epoch_no }} — {{ pendingCountdown }}
          </span>
        </div>
        <div v-if="pendingDiffs.length" class="text-body-2">
          <div v-for="d in pendingDiffs" :key="d.label" class="d-flex" style="gap: 0.5rem;">
            <span class="text-medium-emphasis" style="min-width: 120px;">{{ d.label }}:</span>
            <span><code class="text-caption">{{ d.from }}</code></span>
            <span class="text-medium-emphasis">→</span>
            <span class="text-gold"><strong><code class="text-caption">{{ d.to }}</code></strong></span>
          </div>
        </div>
        <div class="text-caption text-medium-emphasis mt-2">
          Tx <code>{{ info.pending.tx_hash.slice(0, 16) }}…</code> —
          <a
            :href="`https://explorer.cardano.org/en/transaction?id=${info.pending.tx_hash}`"
            target="_blank"
            rel="noopener"
          >view on explorer</a>
        </div>
      </v-alert>

      <v-table density="compact">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 200px;">Ticker</td><td><strong class="text-gold">{{ info.meta_json?.ticker ?? '—' }}</strong></td></tr>
          <tr><td class="text-medium-emphasis">Name</td><td>{{ info.meta_json?.name ?? '—' }}</td></tr>
          <tr v-if="info.meta_json?.homepage"><td class="text-medium-emphasis">Homepage</td><td><a v-if="safeHomepage" :href="safeHomepage" target="_blank" rel="noopener">{{ info.meta_json.homepage }}</a><span v-else>{{ info.meta_json.homepage }}</span></td></tr>
          <tr><td class="text-medium-emphasis">Pool ID</td><td><code>{{ info.pool_id_bech32 }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Status</td><td>{{ info.pool_status }}</td></tr>
          <tr><td class="text-medium-emphasis">Margin</td><td>{{ formatMargin(info.margin) }}</td></tr>
          <tr><td class="text-medium-emphasis">Fixed cost</td><td>{{ fmtAda(info.fixed_cost, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Declared pledge</td><td>{{ fmtAda(info.pledge, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Live pledge</td><td>{{ fmtAda(info.live_pledge, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Live stake</td><td>{{ fmtAda(info.live_stake, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Active stake</td><td>{{ fmtAda(info.active_stake, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Saturation</td><td>{{ formatSaturation(info.live_saturation) }}</td></tr>
          <tr><td class="text-medium-emphasis">Delegators</td><td>{{ info.live_delegators ?? '—' }}</td></tr>
          <tr><td class="text-medium-emphasis">Blocks (lifetime)</td><td>{{ info.block_count ?? '—' }}</td></tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { fmtAda } from '@spo-tools/shared-frontend/utils/format'
import NotConfiguredCard from '../components/NotConfiguredCard.vue'
import NotPairedCard from '../components/NotPairedCard.vue'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'
import { extractError } from '@spo-tools/shared-frontend/utils/error'

interface PoolInfoPending {
  tx_hash: string
  active_epoch_no: number
  active_epoch_first_unix: number
  pledge: string | null
  margin: number | null
  fixed_cost: string | null
}

interface PoolMeta {
  ticker?: string
  name?: string
  description?: string
  homepage?: string
}

interface PoolInfoData {
  meta_json: PoolMeta | null
  pool_id_bech32: string
  pool_status: string
  margin: number | null
  fixed_cost: string | null
  pledge: string | null
  live_pledge: string | null
  live_stake: string | null
  active_stake: string | null
  live_saturation: number | null
  live_delegators: number | null
  block_count: number | null
  pending: PoolInfoPending | null
}

const info = ref<PoolInfoData | null>(null)
const error = ref<string | null>(null)
const loading = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)

async function load() {
  loading.value = true
  error.value = null
  try {
    const r = await fetch('/api/pool/info')
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') {
        notConfigured.value = true
        return
      }
      if (err.code === 'not_paired') {
        notPaired.value = true
        return
      }
      throw new Error(err.message)
    }
    notConfigured.value = false
    info.value = await r.json()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

function formatMargin(m: number | null | undefined): string {
  return m == null ? '—' : `${(m * 100).toFixed(2)}%`
}

function formatSaturation(p: number | null | undefined): string {
  return p == null ? '—' : `${p.toFixed(2)}%`
}

// Pool homepage comes from off-chain metadata, which any pool operator
// controls. Binding it straight into an href would let a javascript: or
// data: URL execute when clicked. Render a link only for an absolute
// http(s) URL; anything else falls back to plain text.
function safeUrl(u: string | null | undefined): string | undefined {
  if (!u) return undefined
  try {
    const parsed = new URL(u)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? u : undefined
  } catch {
    return undefined
  }
}

const safeHomepage = computed(() => safeUrl(info.value?.meta_json?.homepage))

interface PendingDiff { label: string; from: string; to: string }

const pendingDiffs = computed<PendingDiff[]>(() => {
  if (!info.value?.pending) return []
  const cur = info.value
  const p = info.value.pending
  const diffs: PendingDiff[] = []
  if (p.fixed_cost && p.fixed_cost !== cur.fixed_cost) {
    diffs.push({ label: 'Fixed cost', from: fmtAda(cur.fixed_cost, 2), to: fmtAda(p.fixed_cost, 2) })
  }
  if (p.pledge && p.pledge !== cur.pledge) {
    diffs.push({ label: 'Pledge', from: fmtAda(cur.pledge, 2), to: fmtAda(p.pledge, 2) })
  }
  if (p.margin !== null && cur.margin !== null && Math.abs(p.margin - cur.margin) > 1e-9) {
    diffs.push({
      label: 'Margin',
      from: `${(cur.margin * 100).toFixed(4)} %`,
      to: `${(p.margin * 100).toFixed(4)} %`,
    })
  }
  return diffs
})

const pendingCountdown = computed(() => {
  if (!info.value?.pending) return ''
  const secs = info.value.pending.active_epoch_first_unix - Math.floor(Date.now() / 1000)
  if (secs <= 0) return 'activating any moment now'
  const days = Math.floor(secs / 86400)
  const hours = Math.floor((secs % 86400) / 3600)
  if (days > 0) return `in ~${days} day${days === 1 ? '' : 's'} ${hours} h`
  return `in ~${hours} h`
})

onMounted(load)
</script>
