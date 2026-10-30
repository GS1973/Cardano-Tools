<template>
  <v-card class="mb-4"><v-card-title>Sign</v-card-title></v-card>

  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />

  <template v-else>
    <v-card v-if="!parsed && !result" class="mb-4">
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
        <div v-if="sourceLabel" class="text-caption mt-2">Signing wallet: <strong class="text-gold">{{ sourceLabel }}</strong></div>
      </v-card-text>
    </v-card>

    <!-- Preview: Payment -->
    <v-card v-if="parsed?.kind === 'payment'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Verify payment before signing</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          Read these values off this air-gapped screen. The signer hashes the transaction body (Blake2b-256)
          and produces a payment witness. Anything not shown here is not in the transaction.
        </p>

        <div class="verify-headline mb-3">
          <div class="vh-label">Sending</div>
          <div class="vh-amount">{{ fmtAda(parsed.request.amount_lovelace) }}</div>
          <div class="vh-label mt-2">To destination address</div>
          <div class="vh-address">{{ parsed.request.destination_address_bech32 }}</div>
        </div>

        <div v-if="parsed.request.assets_sent.length" class="verify-assets mb-3">
          <div class="field-label mb-1">Native assets sent</div>
          <div v-for="(a, i) in parsed.request.assets_sent" :key="i" class="raw-line mb-1">
            {{ a.quantity }} × policy {{ a.policy_hex }}<span v-if="a.asset_name_hex"> · name {{ a.asset_name_hex }}</span>
          </div>
        </div>

        <div class="on-chain-message mb-3">
          <div class="field-label mb-1">On-chain message (CIP-20)</div>
          <template v-if="parsed.request.metadata_msg && parsed.request.metadata_msg.length">
            <div class="text-body-2 mb-1">
              <v-icon size="16" color="warning" class="me-1">mdi-message-alert</v-icon>
              This text is recorded permanently on-chain and signed by your key. Read every line.
            </div>
            <div v-for="(line, i) in parsed.request.metadata_msg" :key="i" class="raw-line mb-1">{{ line }}</div>
          </template>
          <div v-else class="text-medium-emphasis">
            <v-icon size="16" color="success" class="me-1">mdi-shield-check</v-icon>
            No on-chain message.
          </div>
        </div>

        <div class="change-guard mb-3">
          <v-icon size="16" color="success" class="me-1">mdi-shield-check</v-icon>
          Change ({{ fmtAda(parsed.request.change_lovelace) }}) returns to this wallet's own address:
          <code class="text-caption" style="word-break: break-all;">{{ parsed.request.payment_address_bech32 }}</code>
        </div>

        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />

        <div class="field-row">
          <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
          <div class="field"><div class="field-label">Valid until (TTL slot)</div><div class="field-value">{{ fmtTtl(parsed.request.ttl_slot) }}</div></div>
          <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
        </div>

        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <!-- Preview: Pool delegation -->
    <v-card v-if="parsed?.kind === 'pool-delegate'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Verify stake delegation before signing</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer hashes the body and produces payment + stake witnesses. No ADA leaves the wallet
          except the fee<span v-if="parsed.request.register_stake"> and the refundable stake deposit</span>.
        </p>

        <div class="verify-headline mb-3">
          <div class="vh-label">Delegating stake to pool</div>
          <div class="vh-address">{{ parsed.request.pool_id_bech32 }}</div>
        </div>

        <div class="change-guard mb-3">
          <v-icon size="16" color="success" class="me-1">mdi-shield-check</v-icon>
          Change ({{ fmtAda(parsed.request.change_lovelace) }}) returns to this wallet's own address:
          <code class="text-caption" style="word-break: break-all;">{{ parsed.request.payment_address_bech32 }}</code>
        </div>

        <div class="field-stack mb-2">
          <div class="field"><div class="field-label">Stake address</div><div class="field-value"><code class="text-caption">{{ parsed.request.stake_address_bech32 }}</code></div></div>
          <div class="field"><div class="field-label">Stake registration folded in</div><div class="field-value"><strong>{{ parsed.request.register_stake ? 'Yes' : 'No' }}</strong></div></div>
          <div class="field"><div class="field-label">Deposit (locked, refundable)</div><div class="field-value text-gold"><strong>{{ fmtAda(parsed.request.deposit_lovelace) }}</strong></div></div>
        </div>
        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />

        <div class="field-row">
          <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
          <div class="field"><div class="field-label">Valid until (TTL slot)</div><div class="field-value">{{ fmtTtl(parsed.request.ttl_slot) }}</div></div>
          <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
        </div>

        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <!-- Preview: DRep delegation -->
    <v-card v-if="parsed?.kind === 'drep-delegate'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Verify vote delegation before signing</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer hashes the body and produces payment + stake witnesses. No ADA leaves the wallet
          except the fee<span v-if="parsed.request.register_stake"> and the refundable stake deposit</span>.
        </p>

        <div class="verify-headline mb-3">
          <div class="vh-label">Delegating voting power to</div>
          <div class="vh-address">{{ formatTarget(parsed.request.target) }}</div>
        </div>

        <div class="change-guard mb-3">
          <v-icon size="16" color="success" class="me-1">mdi-shield-check</v-icon>
          Change ({{ fmtAda(parsed.request.change_lovelace) }}) returns to this wallet's own address:
          <code class="text-caption" style="word-break: break-all;">{{ parsed.request.payment_address_bech32 }}</code>
        </div>

        <div class="field-stack mb-2">
          <div class="field"><div class="field-label">Stake address</div><div class="field-value"><code class="text-caption">{{ parsed.request.stake_address_bech32 }}</code></div></div>
          <div class="field"><div class="field-label">Stake registration folded in</div><div class="field-value"><strong>{{ parsed.request.register_stake ? 'Yes' : 'No' }}</strong></div></div>
          <div class="field"><div class="field-label">Deposit (locked, refundable)</div><div class="field-value text-gold"><strong>{{ fmtAda(parsed.request.deposit_lovelace) }}</strong></div></div>
        </div>
        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />

        <div class="field-row">
          <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
          <div class="field"><div class="field-label">Valid until (TTL slot)</div><div class="field-value">{{ fmtTtl(parsed.request.ttl_slot) }}</div></div>
          <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
        </div>

        <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
          <v-btn color="primary" :loading="signing" prepend-icon="mdi-key-variant" @click="confirmAndSign">Confirm and sign</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <!-- Preview: Reward withdrawal -->
    <v-card v-if="parsed?.kind === 'withdraw-rewards'" ref="previewCardEl" class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Verify reward withdrawal before signing</h3>
        <p class="text-body-2 text-medium-emphasis mb-3">
          The signer hashes the body and produces payment + stake witnesses. The rewards are added to this
          wallet's own payment address. No ADA leaves the wallet except the fee.
        </p>

        <div class="verify-headline mb-3">
          <div class="vh-label">Withdrawing rewards</div>
          <div class="vh-amount">{{ fmtAda(parsed.request.rewards_lovelace) }}</div>
          <div class="vh-label mt-2">From this wallet's own reward account</div>
          <div class="vh-address">{{ parsed.request.stake_address_bech32 }}</div>
        </div>

        <div class="change-guard mb-3">
          <v-icon size="16" color="success" class="me-1">mdi-shield-check</v-icon>
          Rewards plus the funding inputs, less the fee ({{ fmtAda(parsed.request.change_lovelace) }}), return to this wallet's own address:
          <code class="text-caption" style="word-break: break-all;">{{ parsed.request.payment_address_bech32 }}</code>
        </div>

        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />

        <div class="field-row">
          <div class="field"><div class="field-label">Fee</div><div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div></div>
          <div class="field"><div class="field-label">Valid until (TTL slot)</div><div class="field-value">{{ fmtTtl(parsed.request.ttl_slot) }}</div></div>
          <div class="field"><div class="field-label">Tx body size</div><div class="field-value">{{ txSize(parsed.request.tx_body_cbor_hex) }} bytes</div></div>
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
          <p class="text-body-2 text-medium-emphasis mb-2">
            The PIN only proves that you are present at this signer for this request. It says nothing about what the request does: the online tool knows the PIN too. Your protection is the preview you just read.
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
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import QRCode from 'qrcode'
import NotConfiguredCard from '../components/NotConfiguredCard.vue'
import FundingInputs from '../components/FundingInputs.vue'
import NotPairedCard from '../components/NotPairedCard.vue'
import QRScanner from '@wallet-tools/shared-frontend/components/QRScanner.vue'
import { QR_CYCLE_INTERVAL_MS } from '@wallet-tools/shared-frontend/constants/timings'
import { useNotificationStore } from '@wallet-tools/shared-frontend/stores/notification'
import { fmtAda, fmtTtl } from '@wallet-tools/shared-frontend/utils/format'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'
import RequestFingerprintBadge from '@wallet-tools/shared-frontend/components/RequestFingerprintBadge.vue'
import type {
  PaymentRequest,
  PoolDelegateRequest,
  DrepDelegateRequest,
  DrepTarget,
  WithdrawRewardsRequest,
} from '@wallet-tools/shared-frontend/types/wire'

type ParsedRequest =
  | { kind: 'payment'; request: PaymentRequest }
  | { kind: 'pool-delegate'; request: PoolDelegateRequest }
  | { kind: 'drep-delegate'; request: DrepDelegateRequest }
  | { kind: 'withdraw-rewards'; request: WithdrawRewardsRequest }

function formatTarget(t: DrepTarget): string {
  if (t === 'abstain') return 'Abstain'
  if (t === 'no_confidence') return 'No-Confidence'
  return t.drep
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
const ownWallets = ref<{ label: string; address: string }[]>([])
const sourceLabel = computed(() => {
  const addr = parsed.value?.request?.payment_address_bech32
  if (!addr) return null
  return ownWallets.value.find((w) => w.address === addr)?.label ?? null
})

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
    notPaired.value = !d.paired
    ownWallets.value = (d.wallets || [])
      .filter((w: { wallet_address: unknown }) => w.wallet_address)
      .map((w: { label: string; wallet_address: { base_address_bech32: string } }) => ({
        label: w.label,
        address: w.wallet_address.base_address_bech32,
      }))
  } catch {
    // transient; leave defaults
  }
}

onMounted(() => { checkConfigured() })
onUnmounted(() => { if (qrTimer) clearInterval(qrTimer) })
</script>

<style scoped>
.verify-headline {
  background: rgba(var(--wallet-gold-rgb), 0.08);
  border: 1px solid rgba(var(--wallet-gold-rgb), 0.4);
  border-radius: 8px;
  padding: 1rem 1.25rem;
}
.vh-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; color: rgba(255, 255, 255, 0.6); }
.vh-amount { font-size: 2rem; font-weight: 700; color: var(--wallet-gold, #FFD700); line-height: 1.2; }
.vh-address { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 1.05rem; font-weight: 700; word-break: break-all; color: #fff; }
.change-guard {
  font-size: 0.85rem;
  color: rgba(255, 255, 255, 0.8);
  background: rgba(76, 175, 80, 0.08);
  border: 1px solid rgba(76, 175, 80, 0.35);
  border-radius: 6px;
  padding: 0.6rem 0.8rem;
}
.field-stack { display: flex; flex-direction: column; gap: 0.85rem; }
.field-row { display: flex; gap: 1.5rem; flex-wrap: wrap; }
.field-row .field { flex: 1 1 auto; min-width: 120px; }
.field-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: rgba(255, 255, 255, 0.55); margin-bottom: 0.15rem; }
.field-value { font-size: 0.875rem; word-break: break-all; }
.raw-line { font-family: monospace; font-size: 0.72rem; word-break: break-all; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; padding: 0.4rem 0.6rem; }
.ur-list { border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; background: rgba(0,0,0,0.25); max-height: 220px; overflow-y: auto; padding: 0.3rem; }
.ur-row { font-family: monospace; font-size: 0.7rem; word-break: break-all; padding: 0.1rem 0.3rem; color: rgba(255,255,255,0.6); }
.ur-active { color: var(--wallet-gold, #FFD700); }
</style>
