<template>
  <SignFlowLayout title="Send payment" :not-configured="notConfigured" :not-paired="notPaired">
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Send ADA</h3>
        <v-spacer />
        <div class="d-flex" style="gap: 0.5rem;">
          <v-btn size="small" color="primary" :variant="mode === 'send' ? 'tonal' : 'outlined'" :loading="starting" :disabled="!canBuild || !!submitted" prepend-icon="mdi-upload" style="width: 180px;" @click="confirmSendOpen = true">Send to Signer</v-btn>
          <v-btn size="small" color="primary" :variant="mode === 'receive' ? 'tonal' : 'outlined'" :disabled="!request || !!submitted" prepend-icon="mdi-download" style="width: 180px;" @click="enterReceive">Receive from Signer</v-btn>
          <v-btn size="small" variant="tonal" :loading="loading" :disabled="!!submitted" prepend-icon="mdi-refresh" @click="startNewSession">Refresh</v-btn>
        </div>
      </v-card-text>

      <v-card-text class="pt-0">
        <SourceWalletSelect v-model="source" @change="onSourceChange" />
      </v-card-text>

      <v-card-text v-if="error" class="pt-0"><v-alert type="error" density="compact" variant="tonal">{{ error }}</v-alert></v-card-text>
      <v-card-text v-else-if="!preview" class="text-medium-emphasis pt-0">Loading…</v-card-text>
      <v-card-text v-else class="pt-0">
        <v-table density="compact" class="mb-3"><tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">From (payment address)</td><td><code class="text-caption">{{ preview.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Spendable balance</td><td>{{ fmtAda(preview.payment_utxo_total_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">UTxOs available</td><td>{{ preview.payment_utxos.length }}</td></tr>
        </tbody></v-table>

        <template v-if="mode !== 'receive'">
          <h3 class="text-subtitle-1 mt-2 mb-2">Recipient</h3>
          <v-select
            v-if="destItems.length"
            :items="destItems" item-title="title" item-value="value"
            label="Pick from address book (optional)"
            density="compact" variant="outlined" clearable hide-details
            prepend-inner-icon="mdi-book-account" class="mb-2"
            @update:model-value="(v: string | null) => { if (v) destinationAddress = v }"
          />
          <v-text-field
            v-model="destinationAddress"
            label="Destination address (addr1…)"
            placeholder="addr1…, where the funds go"
            density="compact" variant="outlined"
            :error-messages="destinationError" class="mb-2"
          />
          <v-text-field
            v-model="amountAda"
            label="Amount (ADA)"
            placeholder="0.000000"
            type="number" min="0" step="0.000001"
            density="compact" variant="outlined"
            hint="ADA to send. The fee and change are computed by the online tool and shown after Send to Signer."
            persistent-hint
            :error-messages="amountError" class="mb-3"
          />

          <h3 class="text-subtitle-1 mt-2 mb-2">On-chain message (optional)</h3>
          <v-textarea
            v-model="messageText"
            label="CIP-20 message"
            placeholder="One line per message entry"
            density="compact" variant="outlined" rows="2" auto-grow
            hint="Recorded permanently on-chain and signed by your key. Each line ≤ 64 bytes. Shown on the signer for you to verify. Leave empty for no message."
            persistent-hint
            :error-messages="messageError" class="mb-3"
          />

          <h3 class="text-subtitle-1 mt-2 mb-2">Native assets (optional)</h3>
          <template v-if="heldAssets.length">
            <p class="text-caption text-medium-emphasis mb-2">Pick from the tokens this wallet holds and enter the amount in the token's own units. It is sent as indivisible on-chain units (shown under the field): the same value the signer displays for you to verify. Leave empty for a pure-ADA send.</p>
            <div v-for="(a, i) in assets" :key="i" class="asset-row mb-2">
              <v-select
                :items="assetItemsFor(i)" item-title="title" item-value="value"
                :model-value="rowKey(a)"
                label="Token" placeholder="Select a token"
                density="compact" variant="outlined" clearable hide-details
                @update:model-value="(v: string | null) => onPickAsset(i, v)"
              />
              <v-text-field
                v-model="a.quantity" label="Amount"
                density="compact" variant="outlined"
                :error-messages="assetRowError(a)"
                :hint="rowHint(a)" persistent-hint
              />
              <v-btn size="small" variant="text" icon="mdi-delete" @click="removeAsset(i)" />
            </div>
            <v-btn size="small" variant="outlined" prepend-icon="mdi-plus" :disabled="assets.length >= heldAssets.length" @click="addAsset">Add asset</v-btn>
          </template>
          <p v-else class="text-caption text-medium-emphasis mb-0">This wallet holds no native assets: pure-ADA send only.</p>
        </template>
      </v-card-text>
    </v-card>

    <SignFlowPanels :flow="flow" @new-session="startNewSession">
      <template #summary>
        <tr v-if="request"><td class="text-medium-emphasis" style="width: 280px;">Send to</td><td><code class="text-caption">{{ request.destination_address_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Amount</td><td><strong>{{ fmtAda(request.amount_lovelace) }}</strong></td></tr>
        <tr v-if="request && request.assets_sent.length"><td class="text-medium-emphasis">Native assets sent</td><td>
          <div v-for="(a, i) in request.assets_sent" :key="i"><code class="text-caption">{{ a.quantity }} units × {{ a.policy_hex.slice(0, 12) }}…{{ a.asset_name_hex }}</code></div>
        </td></tr>
        <tr v-if="request && request.metadata_msg && request.metadata_msg.length"><td class="text-medium-emphasis">On-chain message</td><td>
          <div v-for="(line, i) in request.metadata_msg" :key="i"><code class="text-caption">{{ line }}</code></div>
        </td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Fee</td><td>{{ fmtAda(request.fee_lovelace) }}</td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Change back to payment</td><td>{{ fmtAda(request.change_lovelace) }}</td></tr>
        <tr v-if="result"><td class="text-medium-emphasis">Witnesses signed</td><td><strong>{{ result.witnesses.length }}</strong> <span class="text-caption text-medium-emphasis">({{ witnessRoles }})</span></td></tr>
      </template>
      <template #submitted-summary>
        <tr v-if="request"><td class="text-medium-emphasis">Sent to</td><td><code class="text-caption">{{ request.destination_address_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Amount</td><td><strong>{{ fmtAda(request.amount_lovelace) }}</strong></td></tr>
      </template>
    </SignFlowPanels>

    <PreSendConfirm v-model="confirmSendOpen" title="Confirm payment" @confirm="onConfirmSend">
      <p class="text-body-2 text-medium-emphasis mb-2">You are about to send <strong>{{ amountAda || '0' }} ADA</strong><span v-if="filledAssets.length"> plus {{ filledAssets.length }} native asset(s)</span><span v-if="metadataMsg"> with an on-chain message ({{ metadataMsg.length }} line{{ metadataMsg.length === 1 ? '' : 's' }})</span> to <code>{{ destinationAddress }}</code>. The fee and change are computed now and shown on the next screen for you to verify before signing.</p>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { fmtAda } from '@wallet-tools/shared-frontend/utils/format'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@wallet-tools/shared-frontend/types/errors'
import SignFlowLayout from '../components/SignFlowLayout.vue'
import SignFlowPanels from '../components/SignFlowPanels.vue'
import SourceWalletSelect from '../components/SourceWalletSelect.vue'
import PreSendConfirm from '@wallet-tools/shared-frontend/components/PreSendConfirm.vue'
import { useSignFlow } from '../composables/useSignFlow'

// `quantity` holds the human amount the operator types (in the token's display
// units); it is converted to raw indivisible units for assets_sent: the unit
// the air-gapped signer verifies.
interface AssetRow { policy_hex: string; asset_name_hex: string; decimals: number; quantity: string }
interface BookEntry { label: string; address: string; kind: string }
// Aggregated holding from the preview's payment_assets (raw `quantity` string).
interface HeldAsset { policy_hex: string; asset_name_hex: string; fingerprint: string; decimals: number; quantity: string }

const preview = ref<any>(null)
const error = ref<string | null>(null)
const loading = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)
const source = ref<string | null>(null)
const destinationAddress = ref('')
const amountAda = ref('')
const messageText = ref('')
const destinationError = ref<string[]>([])
const assets = ref<AssetRow[]>([])
const confirmSendOpen = ref(false)
const bookEntries = ref<BookEntry[]>([])

const flow = useSignFlow('/api/payment')
const { mode, starting, submitted, request, result, enterReceive } = flow
flow.setGuards(() => { notConfigured.value = true }, () => { notPaired.value = true })

const destItems = computed(() =>
  bookEntries.value.map((e) => ({
    title: `${e.label}, ${e.address.slice(0, 15)}…${e.address.slice(-8)}`,
    value: e.address,
  })),
)

// Exact decimal→lovelace conversion (no float rounding): input with more than
// 6 decimals is rejected instead of silently rounded, so the amount in the
// confirm dialog is always the amount that gets built.
const amountLovelace = computed(() => {
  const v = amountAda.value.trim()
  if (!v) return 0
  const raw = toRawUnits(v.startsWith('.') ? `0${v}` : v, 6)
  return raw === null ? NaN : Number(raw)
})
const amountError = computed<string[]>(() => {
  const v = amountAda.value.trim()
  if (!v || Number.isFinite(amountLovelace.value)) return []
  return ['Enter a non-negative ADA amount with at most 6 decimals']
})
// CIP-20 message: one array entry per non-empty line; leading/trailing blank
// lines dropped; empty -> null (an empty array is rejected on the backend).
const byteLen = (s: string) => new TextEncoder().encode(s).length
const messageLines = computed<string[]>(() => {
  const raw = messageText.value.replace(/\r\n/g, '\n').split('\n')
  while (raw.length && raw[raw.length - 1].trim() === '') raw.pop()
  while (raw.length && raw[0].trim() === '') raw.shift()
  return raw
})
const messageError = computed<string[]>(() => {
  const i = messageLines.value.findIndex((l) => byteLen(l) > 64)
  return i >= 0 ? [`Line ${i + 1} exceeds 64 bytes (${byteLen(messageLines.value[i])})`] : []
})
const metadataMsg = computed<string[] | null>(() => (messageLines.value.length ? messageLines.value : null))

const canBuild = computed(() =>
  !!preview.value &&
  destinationAddress.value.trim().startsWith('addr1') &&
  Number.isFinite(amountLovelace.value) &&
  assetRowsValid.value &&
  messageError.value.length === 0 &&
  (amountLovelace.value > 0 || filledAssets.value.length > 0),
)
const witnessRoles = computed(() => (result.value?.witnesses ?? []).map((w: any) => w.role).join(' + '))

// ---- Native-asset picker -------------------------------------------------
// The wallet can only send tokens it already holds, so the choices are the
// aggregated assets the backend put in `payment_assets`. Amounts are entered
// in display units for readability and converted to raw indivisible units
// (BigInt, no floating point) for assets_sent: raw units stay the single
// authoritative figure, shown here and verified on the signer.

const assetKey = (policy_hex: string, asset_name_hex: string) => `${policy_hex}.${asset_name_hex}`

/** Decode a hex asset name to printable ASCII, or '' when it is not printable. */
function hexToName(hex: string): string {
  if (!hex || hex.length % 2 !== 0) return ''
  let s = ''
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.slice(i, i + 2), 16)
    if (Number.isNaN(b) || b < 0x20 || b > 0x7e) return ''
    s += String.fromCharCode(b)
  }
  return s
}

/** Raw integer-unit string -> human display string, trailing zeros trimmed. */
function fmtUnits(raw: string, decimals: number): string {
  const r = BigInt(raw)
  if (decimals <= 0) return r.toString()
  const s = r.toString().padStart(decimals + 1, '0')
  const intPart = s.slice(0, s.length - decimals)
  const frac = s.slice(s.length - decimals).replace(/0+$/, '')
  return frac ? `${intPart}.${frac}` : intPart
}

/** Human display amount -> raw integer units, or null when malformed. */
function toRawUnits(display: string, decimals: number): bigint | null {
  const s = display.trim()
  if (!s) return null
  const re = decimals > 0 ? new RegExp(`^\\d+(\\.\\d{1,${decimals}})?$`) : /^\d+$/
  if (!re.test(s)) return null
  const [intPart, fracPart = ''] = s.split('.')
  const frac = (fracPart + '0'.repeat(decimals)).slice(0, decimals)
  return BigInt(intPart + frac)
}

const heldAssets = computed<HeldAsset[]>(() =>
  (preview.value?.payment_assets ?? []).map((h: any) => ({
    policy_hex: h.policy_hex,
    asset_name_hex: h.asset_name_hex,
    fingerprint: h.fingerprint ?? '',
    decimals: Number(h.decimals ?? 0),
    quantity: String(h.quantity),
  })),
)

const heldByKey = computed(() => {
  const m = new Map<string, HeldAsset>()
  for (const h of heldAssets.value) m.set(assetKey(h.policy_hex, h.asset_name_hex), h)
  return m
})

const assetName = (h: HeldAsset) => hexToName(h.asset_name_hex) || '(unnamed)'

function assetTitle(h: HeldAsset): string {
  const fp = h.fingerprint ? `${h.fingerprint.slice(0, 14)}…` : `policy ${h.policy_hex.slice(0, 8)}…`
  return `${assetName(h)} · ${fp} · ${fmtUnits(h.quantity, h.decimals)} available`
}

const rowKey = (a: AssetRow) => (a.policy_hex ? assetKey(a.policy_hex, a.asset_name_hex) : '')
const rowAsset = (a: AssetRow) => heldByKey.value.get(rowKey(a))
const rowRaw = (a: AssetRow): bigint | null => (rowKey(a) ? toRawUnits(a.quantity, a.decimals) : null)

/** Items for row `i`: every held asset except those already picked elsewhere. */
function assetItemsFor(i: number): { title: string; value: string }[] {
  const takenElsewhere = new Set(
    assets.value.filter((_, j) => j !== i).map(rowKey).filter(Boolean),
  )
  return heldAssets.value
    .filter(h => !takenElsewhere.has(assetKey(h.policy_hex, h.asset_name_hex)))
    .map(h => ({ title: assetTitle(h), value: assetKey(h.policy_hex, h.asset_name_hex) }))
}

function onPickAsset(i: number, key: string | null) {
  const h = key ? heldByKey.value.get(key) : undefined
  assets.value[i].policy_hex = h?.policy_hex ?? ''
  assets.value[i].asset_name_hex = h?.asset_name_hex ?? ''
  assets.value[i].decimals = h?.decimals ?? 0
  assets.value[i].quantity = ''
}

function assetRowError(a: AssetRow): string[] {
  if (!rowKey(a) || !a.quantity.trim()) return []
  const raw = rowRaw(a)
  if (raw === null) return [a.decimals > 0 ? `Number with up to ${a.decimals} decimal places` : 'Whole number only']
  if (raw === 0n) return ['Must be greater than zero']
  const avail = BigInt(rowAsset(a)?.quantity ?? '0')
  if (raw > avail) return [`Exceeds available (${fmtUnits(avail.toString(), a.decimals)})`]
  return []
}

function rowHint(a: AssetRow): string {
  const h = rowAsset(a)
  if (!h) return ''
  const avail = `Available: ${fmtUnits(h.quantity, h.decimals)} ${assetName(h)}`
  const raw = rowRaw(a)
  return raw && raw > 0n ? `${avail}  ·  = ${raw.toString()} units` : avail
}

const assetRowsValid = computed(() =>
  assets.value.every(a => {
    const k = rowKey(a)
    if (!k && !a.quantity.trim()) return true   // untouched row: ignored on build
    if (!k) return false                        // a quantity without a chosen token
    return rowRaw(a) !== null && assetRowError(a).length === 0
  }),
)

// assets_sent payload: raw indivisible units, the unchanged backend/signer contract.
const filledAssets = computed(() =>
  assets.value
    .map(a => ({ policy_hex: a.policy_hex.trim(), asset_name_hex: a.asset_name_hex.trim(), raw: rowRaw(a) }))
    .filter(a => a.policy_hex && a.raw !== null && a.raw > 0n)
    .map(a => ({ policy_hex: a.policy_hex, asset_name_hex: a.asset_name_hex, quantity: a.raw!.toString() })),
)
// --------------------------------------------------------------------------

function addAsset() { assets.value.push({ policy_hex: '', asset_name_hex: '', decimals: 0, quantity: '' }) }
function removeAsset(i: number) { assets.value.splice(i, 1) }

async function loadBook() {
  try {
    const r = await fetch('/api/wallet-config')
    if (!r.ok) return
    const d = await r.json()
    bookEntries.value = (d.address_book || []).map((e: BookEntry) => ({ label: e.label, address: e.address, kind: e.kind }))
  } catch { /* transient */ }
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const url = source.value
      ? `/api/payment/preview?source=${encodeURIComponent(source.value)}`
      : '/api/payment/preview'
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

watch([destinationAddress, amountAda, assets, messageText], () => flow.invalidate(), { deep: true })

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  destinationError.value = []
  if (!destinationAddress.value.trim().startsWith('addr1')) {
    destinationError.value = ['Enter a valid addr1… destination address']
    return
  }
  if (!Number.isFinite(amountLovelace.value)) return // amountError explains under the field
  await flow.start({
    source_address: source.value ?? undefined,
    destination_address: destinationAddress.value.trim(),
    amount_lovelace: amountLovelace.value,
    assets_sent: filledAssets.value,
    metadata_msg: metadataMsg.value,
    pin: payload.pin,
  })
}

function startNewSession() { flow.reset(); load() }
onMounted(loadBook)
</script>

<style scoped>
.asset-row {
  display: grid;
  grid-template-columns: 2.5fr 1fr auto;
  gap: 0.5rem;
  align-items: start;
}
</style>
