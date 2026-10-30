<template>
  <SignFlowLayout
    title="Withdraw rewards"
    :not-configured="notConfigured"
    :not-paired="notPaired"
  >
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Preview</h3>
        <v-spacer />
        <div class="d-flex" style="gap: 0.5rem;">
          <v-btn
            size="small"
            color="primary"
            :variant="mode === 'send' ? 'tonal' : 'outlined'"
            :loading="starting"
            :disabled="!canBuild || !!submitted"
            prepend-icon="mdi-upload"
            style="width: 180px;"
            @click="openConfirmSend"
          >Send to Signer</v-btn>
          <v-btn
            size="small"
            color="primary"
            :variant="mode === 'receive' ? 'tonal' : 'outlined'"
            :disabled="!canBuild || !request || !!submitted"
            prepend-icon="mdi-download"
            style="width: 180px;"
            @click="enterReceive"
          >Receive from Signer</v-btn>
          <v-btn
            size="small"
            variant="tonal"
            :loading="loading"
            :disabled="!!submitted"
            prepend-icon="mdi-refresh"
            @click="startNewSession"
          >Refresh</v-btn>
        </div>
      </v-card-text>

      <v-card-text v-if="error">
        <v-alert type="error" density="compact" variant="tonal">{{ error }}</v-alert>
      </v-card-text>

      <v-card-text v-else-if="!preview" class="text-medium-emphasis">Loading…</v-card-text>

      <v-card-text v-else>
        <v-alert
          v-if="!preview.has_rewards"
          type="info"
          density="compact"
          variant="tonal"
          class="mb-4"
        >No rewards available to withdraw on this pool's reward account at this time.</v-alert>

        <v-alert
          v-if="!preview.can_cover_fee"
          type="warning"
          density="compact"
          variant="tonal"
          class="mb-4"
        >Payment address has insufficient funds to cover the transaction fee
          ({{ fmtAda(preview.estimated_fee_lovelace) }}). Top it up before continuing.</v-alert>

        <v-table density="compact">
          <tbody>
            <tr><td class="text-medium-emphasis" style="width: 320px;">Pool reward account</td>
                <td><code class="text-caption">{{ preview.pool_reward_address }}</code></td></tr>
            <tr><td class="text-medium-emphasis">Rewards available to withdraw</td>
                <td class="text-gold"><strong>{{ fmtAda(preview.rewards_available_lovelace) }}</strong></td></tr>
            <tr><td class="text-medium-emphasis">Payment address (funds the fee)</td>
                <td><code class="text-caption">{{ preview.payment_address }}</code></td></tr>
            <tr>
              <td class="text-medium-emphasis">Payment UTXOs</td>
              <td>
                <div v-for="u in preview.payment_utxos" :key="`${u.tx_hash}#${u.tx_index}`" class="text-caption">
                  <code>{{ u.tx_hash.slice(0, 16) }}…#{{ u.tx_index }}</code>,
                  &nbsp;{{ fmtAda(u.lovelace) }}
                </div>
                <div v-if="!preview.payment_utxos.length" class="text-caption text-medium-emphasis">none</div>
              </td>
            </tr>
            <tr><td class="text-medium-emphasis">Payment total</td><td>{{ fmtAda(preview.payment_utxo_total_lovelace) }}</td></tr>
            <tr><td class="text-medium-emphasis">Estimated fee</td><td>{{ fmtAda(preview.estimated_fee_lovelace) }}</td></tr>
            <tr><td class="text-medium-emphasis">Reward receive address</td>
                <td><code class="text-caption">{{ preview.reward_receive_address }}</code></td></tr>
            <tr v-if="request"><td class="text-medium-emphasis">Change back to payment address</td>
                <td>{{ fmtAda(preview.change_to_payment_address_lovelace) }}</td></tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>

    <v-card v-if="startError" class="mb-4">
      <v-card-text>
        <v-alert type="error" density="compact" variant="tonal">{{ startError }}</v-alert>
      </v-card-text>
    </v-card>

    <SendQrPanel
      v-if="request && mode === 'send'"
      ref="sendCardEl"
      :qr-data-url="qrDataUrl"
      :qr-fragments="qrFragments"
      :qr-index="qrIndex"
      :fingerprint="requestFingerprint"
      title="Request"
      @copy="copyUr"
    />

    <ReceiveQrPanel
      v-if="mode === 'receive'"
      ref="receiveCardEl"
      v-model:result-input="resultInput"
      v-model:camera-enlarged="cameraEnlarged"
      :retrying-camera="retryingCamera"
      :result-error="resultError"
      :submitting="submitting"
      @scanner-complete="onScannerComplete"
      @scanner-complete-enlarged="onScannerCompleteEnlarged"
      @scanner-error="(m: string) => resultError = m"
      @retry-camera="retryCamera"
      @submit="submitPasted"
    />

    <v-card ref="resultCardEl" v-if="result && !submitted">
      <v-card-text>
        <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
          <v-icon icon="mdi-check-circle" color="success" />
          <h3 class="text-subtitle-1 mt-0 mb-0">Signed and ready to submit</h3>
        </div>

        <v-alert v-if="!request" type="warning" density="compact" variant="tonal" class="mb-3">
          Result received, but the original transaction is not in this session. Click <strong>Send to Signer</strong> first to build a fresh tx, then receive the signed result for that build.
        </v-alert>

        <v-table density="compact" class="mb-4">
          <tbody>
            <tr v-if="request">
              <td class="text-medium-emphasis" style="width: 280px;">Withdrawing from pool reward account</td>
              <td class="text-gold"><strong>{{ fmtAda(request.net_to_reward_address_lovelace) }}</strong></td>
            </tr>
            <tr v-if="request">
              <td class="text-medium-emphasis">Reward receive address</td>
              <td><code class="text-caption">{{ request.reward_receive_address_bech32 }}</code></td>
            </tr>
            <tr v-if="request">
              <td class="text-medium-emphasis">Change back to payment address</td>
              <td>{{ fmtAda(request.change_to_payment_address_lovelace) }}</td>
            </tr>
            <tr v-if="request">
              <td class="text-medium-emphasis">Fee</td>
              <td>{{ fmtAda(request.fee_lovelace) }}</td>
            </tr>
            <tr v-if="request">
              <td class="text-medium-emphasis">Valid until slot</td>
              <td>{{ fmtInt(request.ttl_slot) }}</td>
            </tr>
            <tr>
              <td class="text-medium-emphasis">Witnesses signed</td>
              <td>
                <strong>{{ result.witnesses.length }}</strong>
                <span class="text-caption text-medium-emphasis"> ({{ result.witnesses.map(w => w.role).join(' + ') }})</span>
              </td>
            </tr>
          </tbody>
        </v-table>

        <v-expansion-panels v-model="rawOpen" class="mb-3" variant="accordion">
          <v-expansion-panel>
            <v-expansion-panel-title class="text-body-2">{{ rawOpen === 0 ? 'Hide raw data' : 'Show raw data' }}</v-expansion-panel-title>
            <v-expansion-panel-text>
              <div class="text-caption text-medium-emphasis mb-1">Body hash (Blake2b-256)</div>
              <div class="raw-line mb-3">{{ result.body_hash_hex }}</div>

              <template v-if="request">
              <div class="text-caption text-medium-emphasis mb-1">Tx body CBOR (hex)</div>
              <div class="raw-line mb-3">{{ request.tx_body_cbor_hex }}</div>
              </template>

              <div v-for="w in result.witnesses" :key="w.role" class="mb-3">
                <div class="text-caption text-medium-emphasis mb-1">Witness: {{ w.role }}</div>
                <div class="text-caption text-medium-emphasis">vkey</div>
                <div class="raw-line mb-1">{{ w.vkey_hex }}</div>
                <div class="text-caption text-medium-emphasis">signature</div>
                <div class="raw-line">{{ w.signature_hex }}</div>
              </div>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>

        <v-alert v-if="submitError" type="error" density="compact" variant="tonal" class="mb-3">
          {{ submitError }}
        </v-alert>

        <div class="d-flex justify-end" style="gap: 0.5rem;" v-if="!submitted">
          <v-btn
                       variant="text"
            prepend-icon="mdi-restart"
            @click="startNewSession"
          >Start new session</v-btn>
          <v-btn
            color="primary"
            :loading="finalSubmitting"
            :disabled="!request"
            prepend-icon="mdi-send"
            @click="submitToChain"
          >Submit to chain</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <v-card v-if="submitted" class="mt-4">
      <v-card-text>
        <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
          <v-icon icon="mdi-check-circle" color="success" />
          <h3 class="text-subtitle-1 mt-0 mb-0">Submitted to Cardano</h3>
        </div>
        <v-table density="compact" class="mb-3">
          <tbody>
            <tr>
              <td class="text-medium-emphasis" style="width: 280px;">Transaction hash</td>
              <td><code class="text-caption">{{ submitted.tx_hash }}</code></td>
            </tr>
            <tr v-if="request">
              <td class="text-medium-emphasis">Withdrawn to reward address</td>
              <td class="text-gold"><strong>{{ fmtAda(request.net_to_reward_address_lovelace) }}</strong></td>
            </tr>
            <tr v-if="request">
              <td class="text-medium-emphasis">Fee</td>
              <td>{{ fmtAda(request.fee_lovelace) }}</td>
            </tr>
            <tr>
              <td class="text-medium-emphasis">Signed tx size</td>
              <td>{{ submitted.signed_tx_size_bytes }} bytes</td>
            </tr>
          </tbody>
        </v-table>

        <v-expansion-panels v-if="request && result" v-model="rawOpen" class="mb-3" variant="accordion">
          <v-expansion-panel>
            <v-expansion-panel-title class="text-body-2">{{ rawOpen === 0 ? 'Hide raw data' : 'Show raw data' }}</v-expansion-panel-title>
            <v-expansion-panel-text>
              <div class="text-caption text-medium-emphasis mb-1">Body hash (Blake2b-256)</div>
              <div class="raw-line mb-3">{{ result.body_hash_hex }}</div>

              <div class="text-caption text-medium-emphasis mb-1">Tx body CBOR (hex)</div>
              <div class="raw-line mb-3">{{ request.tx_body_cbor_hex }}</div>

              <div v-for="w in result.witnesses" :key="w.role" class="mb-3">
                <div class="text-caption text-medium-emphasis mb-1">Witness: {{ w.role }}</div>
                <div class="text-caption text-medium-emphasis">vkey</div>
                <div class="raw-line mb-1">{{ w.vkey_hex }}</div>
                <div class="text-caption text-medium-emphasis">signature</div>
                <div class="raw-line">{{ w.signature_hex }}</div>
              </div>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>

        <div class="d-flex" style="gap: 0.5rem;">
          <v-btn
            color="primary"
            variant="tonal"
            prepend-icon="mdi-open-in-new"
            :href="submitted.explorer_url"
            target="_blank"
            rel="noopener"
          >Open on Cardano Explorer</v-btn>
          <v-btn
            variant="text"
            prepend-icon="mdi-restart"
            @click="startNewSession"
          >Start new session</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <PreSendConfirm
      v-model="confirmSendOpen"
      title="Confirm reward withdrawal"
      @confirm="onConfirmSend"
    >
      <p class="text-body-2 text-medium-emphasis mb-2">You are about to authorise a withdrawal of pool rewards.</p>
      <v-table v-if="preview" density="compact">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 220px;">Pool reward account</td><td><code class="text-caption">{{ preview.pool_reward_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Net amount</td><td class="text-gold"><strong>{{ fmtAda(preview.rewards_available_lovelace) }}</strong></td></tr>
          <tr><td class="text-medium-emphasis">Reward receive</td><td><code class="text-caption">{{ preview.reward_receive_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Fee (estimated)</td><td>{{ fmtAda(preview.estimated_fee_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">Payment change</td><td>{{ fmtAda(preview.change_to_payment_address_lovelace) }} → <code class="text-caption">{{ preview.payment_address }}</code></td></tr>
        </tbody>
      </v-table>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { fmtAda, fmtInt } from '@spo-tools/shared-frontend/utils/format'
import SignFlowLayout from '../components/SignFlowLayout.vue'
import SendQrPanel from '@spo-tools/shared-frontend/components/SendQrPanel.vue'
import ReceiveQrPanel from '@spo-tools/shared-frontend/components/ReceiveQrPanel.vue'
import { useQrCarousel } from '@spo-tools/shared-frontend/composables/useQrCarousel'
import { useScannerControl } from '@spo-tools/shared-frontend/composables/useScannerControl'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'
import type { WithdrawalRequest, WithdrawalResult } from '@spo-tools/shared-frontend/types/wire'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import PreSendConfirm from '@spo-tools/shared-frontend/components/PreSendConfirm.vue'

interface UtxoSummary {
  tx_hash: string
  tx_index: number
  lovelace: number
}
interface WithdrawPreviewData {
  pool_id_bech32: string
  pool_reward_address: string
  reward_receive_address: string
  payment_address: string
  rewards_available_lovelace: number
  payment_utxos: UtxoSummary[]
  payment_utxo_total_lovelace: number
  estimated_fee_lovelace: number
  net_to_reward_address_lovelace: number
  change_to_payment_address_lovelace: number
  can_cover_fee: boolean
  has_rewards: boolean
}



const preview = ref<WithdrawPreviewData | null>(null)
const error = ref<string | null>(null)
const requestFingerprint = ref<string | null>(null)
const confirmSendOpen = ref(false)
const {
  fragments: qrFragments,
  index: qrIndex,
  dataUrl: qrDataUrl,
  renderCurrentFrame,
  startCycle: startQrCycle,
  stopCycle,
  reset: resetQrCarousel,
  copyToClipboard: copyUr,
} = useQrCarousel()
const {
  scannerRef,
  retryingCamera,
  retry: retryCamera,
} = useScannerControl()

const loading = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)

const mode = ref<'idle' | 'send' | 'receive'>('idle')
const starting = ref(false)
const submitting = ref(false)
const startError = ref<string | null>(null)
const resultError = ref<string | null>(null)
const request = ref<WithdrawalRequest | null>(null)
// body_hash_hex from the /start response; a received result must hash-match
// it before it is accepted (stale-result guard).
const bodyHashHex = ref<string | null>(null)
const resultInput = ref('')
const result = ref<WithdrawalResult | null>(null)
const cameraEnlarged = ref(false)
const rawOpen = ref<number | null>(null)

interface SubmittedTx {
  tx_hash: string
  explorer_url: string
  signed_tx_size_bytes: number
}
const submitted = ref<SubmittedTx | null>(null)
const submitError = ref<string | null>(null)
const finalSubmitting = ref(false)

const notify = useNotificationStore()

const sendCardEl = ref<{ $el: HTMLElement } | null>(null)
const receiveCardEl = ref<{ $el: HTMLElement; retry?: () => Promise<void> } | null>(null)
// ReceiveQrPanel exposes retry(); mirror its template ref into the scanner
// control so the error alert's 'Try again' restarts the camera instead of
// no-oping on a never-assigned scannerRef.
watch(receiveCardEl, (el) => { scannerRef.value = el })
const resultCardEl = ref<{ $el: HTMLElement } | null>(null)


const canBuild = computed(
  () => !!preview.value && preview.value.has_rewards && preview.value.can_cover_fee
)

async function load() {
  loading.value = true
  error.value = null
  try {
    const r = await fetch('/api/withdraw/preview')
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
    preview.value = await r.json()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

async function enterReceive() {
  resetQrCarousel()
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'receive'
  await nextTick()
  receiveCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}

function openConfirmSend() {
  // Open the pre-send confirmation modal. The actual fetch runs only
  // after the operator clicks Confirm in the modal.
  confirmSendOpen.value = true
}

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  await startWithdrawal(payload.pin)
}

async function startWithdrawal(pin: string) {
  resetQrCarousel()
  request.value = null
  bodyHashHex.value = null
  result.value = null
  resultInput.value = ''
  startError.value = null
  resultError.value = null
  mode.value = 'send'
  starting.value = true

  try {
    const r = await fetch('/api/withdraw/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin }),
    })
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
    const data = await r.json()
    request.value = data.request
    bodyHashHex.value = data.body_hash_hex || null
    qrFragments.value = data.ur_fragments
    requestFingerprint.value = data.request_fingerprint || null
    qrIndex.value = 0
    await renderCurrentFrame()
    startQrCycle()
    await nextTick()
    sendCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    startError.value = e instanceof Error ? e.message : String(e)
  } finally {
    starting.value = false
  }
}


async function submitFragments(fragments: string[]) {
  submitting.value = true
  resultError.value = null
  try {
    if (!fragments.length) throw new Error('no UR fragments to submit')
    const r = await fetch('/api/withdraw/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
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
    const data = await r.json()
    // Correlate the result with the pending request: a leftover result for
    // an earlier (cancelled/rebuilt) request must not be shown as ready to
    // submit: its witnesses sign a different tx body.
    if (bodyHashHex.value && data.body_hash_hex !== bodyHashHex.value) {
      throw new Error('signed result does not match the pending request (tx body hash differs): scan the result for the request shown above')
    }
    result.value = data
    notify.success(`Signed result received: ${data.witnesses.length} witnesses`)
    await nextTick()
    resultCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    stopCycle()
  } catch (e: unknown) {
    resultError.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

async function onScannerComplete(fragments: string[]) {
  await submitFragments(fragments)
}

async function onScannerCompleteEnlarged(fragments: string[]) {
  cameraEnlarged.value = false
  await submitFragments(fragments)
}

async function submitPasted() {
  const fragments = resultInput.value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  await submitFragments(fragments)
}

async function submitToChain() {
  if (!request.value || !result.value) return
  finalSubmitting.value = true
  submitError.value = null
  try {
    const r = await fetch('/api/withdraw/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tx_body_cbor_hex: request.value.tx_body_cbor_hex,
        witnesses: result.value.witnesses,
      }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      throw new Error(err.message)
    }
    submitted.value = await r.json()
    notify.success(`Tx submitted: ${submitted.value!.tx_hash.slice(0, 16)}…`)
  } catch (e: unknown) {
    submitError.value = e instanceof Error ? e.message : String(e)
  } finally {
    finalSubmitting.value = false
  }
}

function startNewSession() {
  submitted.value = null
  submitError.value = null
  result.value = null
  request.value = null
  bodyHashHex.value = null
  resultInput.value = ''
  qrFragments.value = []
  requestFingerprint.value = null
  qrDataUrl.value = null
  qrIndex.value = 0
  startError.value = null
  resultError.value = null
  rawOpen.value = null
  mode.value = 'idle'
  stopCycle()
  load()
}


onMounted(load)
</script>
