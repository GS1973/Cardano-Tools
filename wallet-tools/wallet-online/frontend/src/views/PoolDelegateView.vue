<template>
  <SignFlowLayout title="Delegate stake to a pool" :not-configured="notConfigured" :not-paired="notPaired">
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Delegate stake</h3>
        <v-spacer />
        <div class="d-flex" style="gap: 0.5rem;">
          <v-btn size="small" color="primary" :variant="mode === 'send' ? 'tonal' : 'outlined'" :loading="starting" :disabled="!canBuild || !!submitted" prepend-icon="mdi-upload" style="width: 180px;" @click="confirmSendOpen = true">Send to Signer</v-btn>
          <v-btn size="small" color="primary" :variant="mode === 'receive' ? 'tonal' : 'outlined'" :disabled="!request || !!submitted" prepend-icon="mdi-download" style="width: 180px;" @click="enterReceive">Receive from Signer</v-btn>
          <v-btn size="small" variant="tonal" :loading="loading" :disabled="!!submitted" prepend-icon="mdi-refresh" @click="startNewSession">Refresh</v-btn>
        </div>
      </v-card-text>

      <v-card-text class="pt-0">
        <SourceWalletSelect v-model="source" :delegatable-only="true" @change="onSourceChange" />
      </v-card-text>

      <v-card-text v-if="error" class="pt-0"><v-alert type="error" density="compact" variant="tonal">{{ error }}</v-alert></v-card-text>
      <v-card-text v-else-if="!preview" class="text-medium-emphasis pt-0">Loading…</v-card-text>
      <v-card-text v-else class="pt-0">
        <v-alert v-if="preview.register_stake" type="info" density="compact" variant="tonal" class="mb-4">This stake key is not registered yet. A stake-registration certificate will be folded into this transaction, locking a refundable deposit of <strong>{{ fmtAda(preview.deposit_lovelace) }}</strong>.</v-alert>

        <v-table density="compact" class="mb-3"><tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">Payment address</td><td><code class="text-caption">{{ preview.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Stake address (delegated)</td><td><code class="text-caption">{{ preview.stake_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Spendable balance</td><td>{{ fmtAda(preview.payment_utxo_total_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">Stake registration folded in</td><td><strong>{{ preview.register_stake ? 'Yes' : 'No (already registered)' }}</strong></td></tr>
          <tr><td class="text-medium-emphasis">Deposit (locked, refundable)</td><td>{{ fmtAda(preview.deposit_lovelace) }}</td></tr>
          <tr v-if="preview.currently_delegated_pool"><td class="text-medium-emphasis">Currently delegated to</td><td><code class="text-caption">{{ preview.currently_delegated_pool }}</code></td></tr>
        </tbody></v-table>

        <template v-if="mode !== 'receive'">
          <h3 class="text-subtitle-1 mt-2 mb-2">Target pool</h3>
          <v-text-field
            v-model="poolId"
            label="Pool id (pool1…)"
            placeholder="pool1…: the stake pool to delegate to"
            density="compact" variant="outlined"
            :error-messages="poolIdError"
          />
        </template>
      </v-card-text>
    </v-card>

    <SignFlowPanels :flow="flow" @new-session="startNewSession">
      <template #summary>
        <tr v-if="request"><td class="text-medium-emphasis" style="width: 280px;">Delegate stake to</td><td><code class="text-caption">{{ request.pool_id_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Stake address</td><td><code class="text-caption">{{ request.stake_address_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Stake registration folded in</td><td><strong>{{ request.register_stake ? 'Yes' : 'No' }}</strong></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Deposit</td><td>{{ fmtAda(request.deposit_lovelace) }}</td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Fee</td><td>{{ fmtAda(request.fee_lovelace) }}</td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Change back to payment</td><td>{{ fmtAda(request.change_lovelace) }}</td></tr>
        <tr v-if="result"><td class="text-medium-emphasis">Witnesses signed</td><td><strong>{{ result.witnesses.length }}</strong> <span class="text-caption text-medium-emphasis">({{ witnessRoles }})</span></td></tr>
      </template>
      <template #submitted-summary>
        <tr v-if="request"><td class="text-medium-emphasis">Delegated to pool</td><td><code class="text-caption">{{ request.pool_id_bech32 }}</code></td></tr>
      </template>
    </SignFlowPanels>

    <PreSendConfirm v-model="confirmSendOpen" title="Confirm stake delegation" @confirm="onConfirmSend">
      <p class="text-body-2 text-medium-emphasis mb-2">You are about to delegate this wallet's stake to <code>{{ poolId }}</code><span v-if="preview && preview.register_stake">, registering the stake key and locking a refundable deposit of <strong>{{ fmtAda(preview.deposit_lovelace) }}</strong></span>.</p>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { fmtAda } from '@wallet-tools/shared-frontend/utils/format'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@wallet-tools/shared-frontend/types/errors'
import SignFlowLayout from '../components/SignFlowLayout.vue'
import SignFlowPanels from '../components/SignFlowPanels.vue'
import SourceWalletSelect from '../components/SourceWalletSelect.vue'
import PreSendConfirm from '@wallet-tools/shared-frontend/components/PreSendConfirm.vue'
import { useSignFlow } from '../composables/useSignFlow'

const preview = ref<any>(null)
const error = ref<string | null>(null)
const loading = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)
const source = ref<string | null>(null)
const poolId = ref('')
const poolIdError = ref<string[]>([])
const confirmSendOpen = ref(false)

const flow = useSignFlow('/api/pool-delegate')
const { mode, starting, submitted, request, result, enterReceive } = flow
flow.setGuards(() => { notConfigured.value = true }, () => { notPaired.value = true })

const canBuild = computed(() => !!preview.value && poolId.value.trim().startsWith('pool1'))
const witnessRoles = computed(() => (result.value?.witnesses ?? []).map((w: any) => w.role).join(' + '))

async function load() {
  loading.value = true
  error.value = null
  try {
    const url = source.value
      ? `/api/pool-delegate/preview?source=${encodeURIComponent(source.value)}`
      : '/api/pool-delegate/preview'
    const r = await fetch(url)
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') { notConfigured.value = true; return }
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    preview.value = await r.json()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

function onSourceChange() { flow.invalidate(); load() }
watch(poolId, () => flow.invalidate())

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  poolIdError.value = []
  if (!poolId.value.trim().startsWith('pool1')) {
    poolIdError.value = ['Enter a valid pool1… pool id']
    return
  }
  await flow.start({
    source_address: source.value ?? undefined,
    pool_id: poolId.value.trim(),
    pin: payload.pin,
  })
}

function startNewSession() { flow.reset(); load() }
</script>
