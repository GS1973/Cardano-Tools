<template>
  <v-card class="mb-4"><v-card-title>Sign</v-card-title></v-card>

  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />

  <template v-else>
    <v-card v-if="!parsed" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Awaiting request</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          Scan the QR shown by the online tool, or paste the UR fragments and click Submit.
        </p>
        <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
          <div v-if="!cameraEnlarged" class="d-flex flex-column align-center" style="flex: 0 0 auto;">
            <div style="width: 160px;">
              <QRScanner ref="scannerRef" @complete="onScannerComplete" @error="(m: string) => (receiveError = m)" />
            </div>
            <v-btn class="mt-2" size="small" variant="text" prepend-icon="mdi-arrow-expand" @click="cameraEnlarged = true">Enlarge</v-btn>
          </div>
          <div style="flex: 1 1 auto; min-width: 0;">
            <!-- Placeholder mirrors airgap-core's UR_TYPE_ACTION tag ("spo-tools-action-v2"), shared across products — not a typo. -->
            <v-textarea v-model="pasteInput" label="UR fragments from the online tool" rows="6" variant="outlined" density="compact" hide-details placeholder="ur:spo-tools-action-v2/..." />
            <v-btn class="mt-2" color="primary" :loading="receiving" :disabled="!pasteInput.trim()" prepend-icon="mdi-upload" @click="submitPasted">Submit</v-btn>
          </div>
        </div>
        <v-alert v-if="receiveError" type="error" density="compact" variant="tonal" class="mt-3">
          {{ receiveError }}
          <template #append>
            <v-btn size="x-small" variant="text" :loading="retryingCamera" class="text-white" prepend-icon="mdi-refresh" @click="retryCamera">Try again</v-btn>
          </template>
        </v-alert>
      </v-card-text>
    </v-card>

    <v-card v-if="parsed && requestFingerprint" class="mb-4">
      <v-card-text class="py-3">
        <RequestFingerprintBadge :fingerprint="requestFingerprint" />
        <p class="text-caption text-medium-emphasis mt-2 mb-0">
          This must match the fingerprint shown next to the QR on the online tool. If they differ, do not sign.
        </p>
      </v-card-text>
    </v-card>

    <!-- Preview: DRep register -->
    <v-card v-if="parsed?.kind === 'drep-register'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Register DRep</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer will hash the supplied transaction body (Blake2b-256) and produce two vkey witnesses: payment (fee + deposit) and DRep (cert authority). The DRep key must hash to the DRep id below or the signer refuses.
        </p>
        <div class="field-stack">
          <div class="field"><div class="field-label">Register DRep</div><div class="field-value"><code class="text-caption">{{ parsed.request.drep_id_bech32 }}</code></div></div>
          <div class="field"><div class="field-label">Deposit (locked, refundable)</div><div class="field-value text-gold"><strong>{{ fmtAda(parsed.request.deposit_lovelace) }}</strong></div></div>
          <div class="field"><div class="field-label">Manifest anchor (CIP-119)</div><div class="field-value"><code v-if="parsed.request.anchor" class="text-caption">{{ parsed.request.anchor.url }}</code><span v-else class="text-caption text-medium-emphasis">(none)</span><div v-if="parsed.request.anchor" class="text-caption text-medium-emphasis mt-1">hash {{ parsed.request.anchor.hash_hex }}</div></div></div>
          <div class="field"><div class="field-label">Payment address</div><div class="field-value"><code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code></div></div>
          <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
          <div class="field-row">
            <div class="field"><div class="field-label">Change to payment</div><div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div></div>
            <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
            <div class="field"><div class="field-label">TTL slot</div><div class="field-value">{{ Number(parsed.request.ttl_slot).toLocaleString() }}</div></div>
            <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
          </div>
        </div>
        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <!-- Preview: DRep update -->
    <v-card v-if="parsed?.kind === 'drep-update'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Update / refresh DRep</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer will hash the body and produce payment + DRep witnesses. This resets the activity counter (keep-alive) and, if an anchor is set, points the on-chain manifest at it.
        </p>
        <div class="field-stack">
          <div class="field"><div class="field-label">Update DRep</div><div class="field-value"><code class="text-caption">{{ parsed.request.drep_id_bech32 }}</code></div></div>
          <div class="field"><div class="field-label">Manifest anchor (CIP-119)</div><div class="field-value"><code v-if="parsed.request.anchor" class="text-caption">{{ parsed.request.anchor.url }}</code><span v-else class="text-caption text-medium-emphasis">(keep-alive, no anchor)</span><div v-if="parsed.request.anchor" class="text-caption text-medium-emphasis mt-1">hash {{ parsed.request.anchor.hash_hex }}</div></div></div>
          <div class="field"><div class="field-label">Payment address</div><div class="field-value"><code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code></div></div>
          <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
          <div class="field-row">
            <div class="field"><div class="field-label">Change to payment</div><div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div></div>
            <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
            <div class="field"><div class="field-label">TTL slot</div><div class="field-value">{{ Number(parsed.request.ttl_slot).toLocaleString() }}</div></div>
            <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
          </div>
        </div>
        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <!-- Preview: DRep retire -->
    <v-card v-if="parsed?.kind === 'drep-retire'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Retire DRep</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer will hash the body and produce payment + DRep witnesses. The deposit is refunded to the payment address.
        </p>
        <div class="field-stack">
          <div class="field"><div class="field-label">Retire DRep</div><div class="field-value"><code class="text-caption">{{ parsed.request.drep_id_bech32 }}</code></div></div>
          <div class="field"><div class="field-label">Deposit refund</div><div class="field-value text-gold"><strong>{{ fmtAda(parsed.request.deposit_refund_lovelace) }}</strong></div></div>
          <div class="field"><div class="field-label">Payment address</div><div class="field-value"><code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code></div></div>
          <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
          <div class="field-row">
            <div class="field"><div class="field-label">Change to payment</div><div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div></div>
            <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
            <div class="field"><div class="field-label">TTL slot</div><div class="field-value">{{ Number(parsed.request.ttl_slot).toLocaleString() }}</div></div>
            <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
          </div>
        </div>
        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <!-- Preview: DRep vote -->
    <v-card v-if="parsed?.kind === 'drep-vote'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Preview — DRep governance vote</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer will hash the body and produce payment + DRep witnesses. The DRep key must hash to the DRep id below or the signer refuses.
        </p>
        <div class="field-stack">
          <div class="field"><div class="field-label">Vote</div><div class="field-value text-gold"><strong>{{ formatVote(parsed.request.vote) }}</strong></div></div>
          <div class="field"><div class="field-label">Governance action</div><div class="field-value"><code class="text-caption">{{ parsed.request.action_tx_hash_hex }}#{{ parsed.request.action_index }}</code></div></div>
          <div class="field"><div class="field-label">As DRep</div><div class="field-value"><code class="text-caption">{{ parsed.request.drep_id_bech32 }}</code></div></div>
          <div class="field"><div class="field-label">Rationale anchor (CIP-136)</div><div class="field-value"><code v-if="parsed.request.anchor" class="text-caption">{{ parsed.request.anchor.url }}</code><span v-else class="text-caption text-medium-emphasis">(none)</span><div v-if="parsed.request.anchor" class="text-caption text-medium-emphasis mt-1">hash {{ parsed.request.anchor.hash_hex }}</div></div></div>
          <div class="field"><div class="field-label">Payment address</div><div class="field-value"><code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code></div></div>
          <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
          <div class="field-row">
            <div class="field"><div class="field-label">Change to payment</div><div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div></div>
            <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
            <div class="field"><div class="field-label">TTL slot</div><div class="field-value">{{ Number(parsed.request.ttl_slot).toLocaleString() }}</div></div>
            <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
          </div>
        </div>
        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <v-card v-if="signError" class="mb-4"><v-card-text><v-alert type="error" density="compact" variant="tonal">{{ signError }}</v-alert></v-card-text></v-card>

    <v-card v-if="result" ref="resultCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Result</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          Either show the QR to the online tool's webcam or copy the UR fragments and paste them in the online tool's Receive panel.
        </p>
        <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
          <div class="d-flex flex-column align-center" style="flex: 0 0 auto;">
            <div class="bg-white pa-2 d-flex align-center justify-center" style="border-radius: 8px;">
              <img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 160px; height: 160px;" />
            </div>
            <v-btn class="mt-2" size="small" variant="text" prepend-icon="mdi-arrow-expand" @click="qrEnlarged = true">Enlarge</v-btn>
          </div>
          <div style="flex: 1 1 auto; min-width: 0;">
            <div class="d-flex align-center justify-end mb-1" style="gap: 0.75rem;">
              <span v-if="result.ur_fragments.length > 1" class="text-caption text-medium-emphasis">{{ qrIndex + 1 }} / {{ result.ur_fragments.length }}</span>
              <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyResultUr">Copy</v-btn>
            </div>
            <div class="ur-list">
              <div v-for="(f, i) in result.ur_fragments" :key="i" :class="['ur-row', { 'ur-active': i === qrIndex }]">{{ f }}</div>
            </div>
          </div>
        </div>
        <div class="d-flex justify-end mt-3">
          <v-btn variant="text" prepend-icon="mdi-restart" @click="startNewSession">Start new session</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <v-dialog v-model="qrEnlarged" max-width="640">
      <v-card><v-card-text class="d-flex flex-column align-center pa-6">
        <div class="bg-white pa-4" style="border-radius: 8px;"><img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 480px; height: 480px;" /></div>
        <div v-if="result && result.ur_fragments.length > 1" class="text-caption text-medium-emphasis mt-2">{{ qrIndex + 1 }} / {{ result.ur_fragments.length }}</div>
        <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="qrEnlarged = false">Shrink</v-btn>
      </v-card-text></v-card>
    </v-dialog>

    <v-dialog v-model="cameraEnlarged" max-width="640">
      <v-card><v-card-text class="d-flex flex-column align-center pa-6">
        <div style="width: 480px;">
          <QRScanner v-if="cameraEnlarged" @complete="onScannerCompleteEnlarged" @error="(m: string) => { receiveError = m; cameraEnlarged = false }" />
        </div>
        <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="cameraEnlarged = false">Shrink</v-btn>
      </v-card-text></v-card>
    </v-dialog>

    <v-dialog v-model="pinDialogOpen" max-width="480" persistent>
      <v-card>
        <v-card-title>Confirm operator PIN</v-card-title>
        <v-card-text>
          <p class="text-body-2 mb-2">
            Type the same 4-digit PIN you entered on the online tool when you clicked Send to Signer. The signer hashes your input and refuses to sign if it does not match the PIN encoded in the encrypted payload.
          </p>
          <v-text-field v-model="pinInput" density="compact" variant="outlined" type="password" inputmode="numeric" maxlength="4" placeholder="0000" :error-messages="pinError ? [pinError] : []" hide-details="auto" autofocus style="max-width: 160px;" @keydown.enter="executeWithPin" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="pinDialogOpen = false">Cancel</v-btn>
          <v-btn color="primary" prepend-icon="mdi-key-variant" :loading="signing" @click="executeWithPin">Sign</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </template>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import QRCode from 'qrcode'
import NotConfiguredCard from '../components/NotConfiguredCard.vue'
import FundingInputs from '../components/FundingInputs.vue'
import NotPairedCard from '../components/NotPairedCard.vue'
import QRScanner from '@drep-tools/shared-frontend/components/QRScanner.vue'
import { QR_CYCLE_INTERVAL_MS } from '@drep-tools/shared-frontend/constants/timings'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import { fmtAda } from '@drep-tools/shared-frontend/utils/format'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import RequestFingerprintBadge from '@drep-tools/shared-frontend/components/RequestFingerprintBadge.vue'
import type {
  DRepRegisterRequest,
  DRepUpdateRequest,
  DRepRetireRequest,
  DRepVoteRequest,
  VoteChoice,
} from '@drep-tools/shared-frontend/types/wire'

type ParsedRequest =
  | { kind: 'drep-register'; request: DRepRegisterRequest }
  | { kind: 'drep-update'; request: DRepUpdateRequest }
  | { kind: 'drep-retire'; request: DRepRetireRequest }
  | { kind: 'drep-vote'; request: DRepVoteRequest }

function formatVote(v: VoteChoice): string {
  return v === 'yes' ? 'Yes' : v === 'no' ? 'No' : 'Abstain'
}
function txSize(hex: string): number {
  return Math.floor(hex.length / 2)
}

const notify = useNotificationStore()

const parsed = ref<ParsedRequest | null>(null)
const requestFingerprint = ref<string | null>(null)
const pinDialogOpen = ref(false)
const pinInput = ref('')
const pinError = ref<string | null>(null)
const originalFragments = ref<string[]>([])
const pasteInput = ref('')
const receiving = ref(false)
const receiveError = ref<string | null>(null)
const cameraEnlarged = ref(false)
const signing = ref(false)
const signError = ref<string | null>(null)
const result = ref<{ kind: string; ur_fragments: string[] } | null>(null)
const qrEnlarged = ref(false)
const qrIndex = ref(0)
const qrDataUrl = ref<string | null>(null)
let qrTimer: ReturnType<typeof setInterval> | null = null

const scannerRef = ref<{ retry: () => Promise<void> } | null>(null)
const retryingCamera = ref(false)
const previewCardEl = ref<{ $el: HTMLElement } | null>(null)
const resultCardEl = ref<{ $el: HTMLElement } | null>(null)

const notConfigured = ref(false)
const notPaired = ref(false)

async function submitFragments(fragments: string[]) {
  receiving.value = true
  receiveError.value = null
  try {
    const r = await fetch('/api/sign/receive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    const rawResp: any = await r.json()
    requestFingerprint.value = rawResp.request_fingerprint || null
    parsed.value = rawResp
    originalFragments.value = fragments
    notify.success(`Received ${parsed.value?.kind} request`)
    await nextTick()
    previewCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    receiveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    receiving.value = false
  }
}

async function onScannerComplete(fragments: string[]) { await submitFragments(fragments) }
async function onScannerCompleteEnlarged(fragments: string[]) { cameraEnlarged.value = false; await submitFragments(fragments) }
async function submitPasted() {
  const fragments = pasteInput.value.split('\n').map((s) => s.trim()).filter(Boolean)
  if (!fragments.length) return
  await submitFragments(fragments)
}

function cancelParse() {
  parsed.value = null
  requestFingerprint.value = null
  originalFragments.value = []
  pasteInput.value = ''
  receiveError.value = null
  signError.value = null
  result.value = null
  qrDataUrl.value = null
  qrIndex.value = 0
  cameraEnlarged.value = false
  qrEnlarged.value = false
  pinDialogOpen.value = false
  pinInput.value = ''
  pinError.value = null
  if (qrTimer) clearInterval(qrTimer)
  qrTimer = null
}

async function retryCamera() {
  retryingCamera.value = true
  receiveError.value = null
  try {
    await scannerRef.value?.retry()
  } finally {
    retryingCamera.value = false
  }
}

function confirmAndSign() {
  if (!originalFragments.value.length) return
  pinInput.value = ''
  pinError.value = null
  pinDialogOpen.value = true
}

async function executeWithPin() {
  if (!/^\d{4}$/.test(pinInput.value)) {
    pinError.value = 'Enter exactly 4 digits'
    return
  }
  pinError.value = null
  pinDialogOpen.value = false
  signing.value = true
  signError.value = null
  try {
    const r = await fetch('/api/sign/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: originalFragments.value, pin: pinInput.value }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    const d = await r.json()
    result.value = d
    parsed.value = null
    requestFingerprint.value = null
    originalFragments.value = []
    pasteInput.value = ''
    qrIndex.value = 0
    await renderCurrentFrame()
    startQrCycle()
    notify.success(`Signed: ${d.kind}`)
    await nextTick()
    resultCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    signError.value = e instanceof Error ? e.message : String(e)
  } finally {
    signing.value = false
  }
}

async function renderCurrentFrame() {
  if (!result.value || !result.value.ur_fragments.length) return
  const fragment = result.value.ur_fragments[qrIndex.value]
  qrDataUrl.value = await QRCode.toDataURL(fragment, { margin: 1, width: 800, errorCorrectionLevel: 'M' })
}

function startQrCycle() {
  if (qrTimer) clearInterval(qrTimer)
  if (!result.value || result.value.ur_fragments.length <= 1) return
  qrTimer = setInterval(async () => {
    qrIndex.value = (qrIndex.value + 1) % (result.value?.ur_fragments.length ?? 1)
    await renderCurrentFrame()
  }, QR_CYCLE_INTERVAL_MS)
}

async function copyResultUr() {
  if (!result.value) return
  try {
    await navigator.clipboard.writeText(result.value.ur_fragments.join('\n'))
    notify.success('Result UR fragments copied to clipboard')
  } catch (e: unknown) {
    notify.error('Could not copy: ' + (e instanceof Error ? e.message : String(e)))
  }
}

function startNewSession() { cancelParse() }

async function checkConfigured() {
  try {
    const r = await fetch('/api/signer-config')
    if (!r.ok) return
    const d = await r.json()
    notConfigured.value = !d.saved
  } catch {
    // transient; leave notConfigured false
  }
}

onMounted(() => { checkConfigured() })
onUnmounted(() => { if (qrTimer) clearInterval(qrTimer) })
</script>

<style scoped>
.field-stack { display: flex; flex-direction: column; gap: 0.85rem; }
.field-row { display: flex; gap: 1.5rem; flex-wrap: wrap; }
.field-row .field { flex: 1 1 auto; min-width: 120px; }
.field-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: rgba(255, 255, 255, 0.55); margin-bottom: 0.15rem; }
.field-value { font-size: 0.875rem; word-break: break-all; }
.ur-list { border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; background: rgba(0,0,0,0.25); max-height: 220px; overflow-y: auto; padding: 0.3rem; }
.ur-row { font-family: monospace; font-size: 0.7rem; word-break: break-all; padding: 0.1rem 0.3rem; color: rgba(255,255,255,0.6); }
.ur-active { color: var(--drep-gold, #FFD700); }
</style>
