<template>
  <v-card class="mb-4"><v-card-title>Setup</v-card-title></v-card>

  <v-alert v-if="loadError" type="error" density="compact" variant="tonal" class="mb-4">{{ loadError }}</v-alert>

  <v-alert type="info" density="compact" variant="tonal" class="mb-4">
    Supports <code>cardano-cli</code> generated <code>.skey</code> files and the extended BIP32 form.
    This signer holds <strong>only</strong> payment and stake keys, never the pool cold key or a DRep key,
    for up to {{ MAX_KEYS }} wallets. A wallet with no stake key is an enterprise (payment-only) address: it can send but not delegate.
  </v-alert>

  <v-card class="mb-4">
    <v-card-text>
      <div class="d-flex align-center mb-2" style="gap: 0.75rem;">
        <v-icon icon="mdi-key-plus" />
        <h3 class="text-subtitle-1 mt-0 mb-0">Generate new wallet keys</h3>
      </div>
      <p class="text-caption text-medium-emphasis mb-3">
        Creates a fresh Ed25519 payment + stake key pair on this air-gapped machine and writes
        <code>payment.skey</code> + <code>stake.skey</code> (and their vkeys) to the chosen directory, then adds it
        to the list below. Pick a folder on your encrypted removable drive: the keys never leave this machine.
        Requires pairing first: the public address export travels back to the online tool over the encrypted QR channel.
      </p>
      <div class="d-flex align-start flex-wrap" style="gap: 0.5rem;">
        <v-text-field
          v-model="genLabel" label="Wallet label" placeholder="e.g. Cold wallet"
          density="compact" variant="outlined" hide-details style="max-width: 220px;"
        />
        <v-text-field
          v-model="genDir" label="Output directory (under /media, /mnt or /run/media)" placeholder="/media/usb/keys"
          density="compact" variant="outlined" hide-details style="min-width: 260px; flex: 1 1 auto;"
        />
        <v-btn size="small" variant="outlined" prepend-icon="mdi-folder-open" class="mt-1" @click="genBrowseOpen = true">Browse</v-btn>
        <v-btn color="primary" :loading="generating" :disabled="!genDir.trim()" prepend-icon="mdi-key-plus" class="mt-1" @click="generateKeys">Generate</v-btn>
      </div>
      <v-alert v-if="genError" type="error" density="compact" variant="tonal" class="mt-3">{{ genError }}</v-alert>

      <template v-if="genResult">
        <v-alert type="success" density="compact" variant="tonal" class="mt-3">
          <div class="mb-1"><strong>Wallet keys generated and added below.</strong> Payment address (carry this to the online tool):</div>
          <div class="d-flex align-center" style="gap: 0.5rem;">
            <code class="text-caption" style="word-break: break-all;">{{ genResult.base_address }}</code>
            <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyText(genResult.base_address, 'Payment address')">Copy</v-btn>
          </div>
        </v-alert>

        <v-card class="mt-3">
          <v-card-text>
            <h3 class="text-subtitle-1 mt-0 mb-2">Export the new address to the online tool</h3>
            <p class="text-body-2 text-medium-emphasis mb-3">
              Show this animated QR to the online tool's webcam (or copy the UR fragments and paste them)
              under <strong>New address</strong> there. It carries only the public address: no secret.
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
                  <span v-if="genResult.ur_fragments.length > 1" class="text-caption text-medium-emphasis">{{ qrIndex + 1 }} / {{ genResult.ur_fragments.length }}</span>
                  <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyExportUr">Copy</v-btn>
                </div>
                <div class="ur-list">
                  <div v-for="(f, i) in genResult.ur_fragments" :key="i" :class="['ur-row', { 'ur-active': i === qrIndex }]">{{ f }}</div>
                </div>
              </div>
            </div>
          </v-card-text>
        </v-card>
      </template>

      <FileBrowserDialog v-model="genBrowseOpen" title="Select output directory" :initial-path="genDir || null" select-dir @pick="(p) => { genDir = p }" />
    </v-card-text>
  </v-card>

  <v-card>
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.75rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Signing keys</h3>
        <v-chip size="small" variant="tonal">{{ entries.length }} / {{ MAX_KEYS }}</v-chip>
        <v-spacer />
        <v-chip :color="paired ? 'success' : 'warning'" size="small" variant="tonal" :prepend-icon="paired ? 'mdi-shield-check' : 'mdi-shield-alert'">
          {{ paired ? `Paired ${pairingFingerprint ?? ''}` : 'Not paired' }}
        </v-chip>
      </div>

      <div v-if="!entries.length" class="text-medium-emphasis text-body-2 mb-3">
        No wallets yet. Generate a pair above, or add one and point it at existing <code>.skey</code> files.
      </div>

      <div v-for="(e, i) in entries" :key="i" class="wallet-entry">
        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <v-text-field v-model="e.label" label="Wallet label" density="compact" variant="outlined" hide-details style="max-width: 280px;" />
          <v-spacer />
          <code v-if="e.wallet_address" class="text-caption text-gold" style="word-break: break-all;">{{ e.wallet_address.base_address_bech32 }}</code>
          <v-btn size="small" variant="text" icon="mdi-delete" @click="remove(i)" />
        </div>
        <KeyField
          v-model="e.payment_skey_path"
          label="Payment signing key"
          powers="spending input UTxOs + transaction fees"
          kind="payment"
          :status="e.payment_skey"
          @test="testLoad(e, 'payment')"
        />
        <KeyField
          v-model="e.stake_skey_path"
          label="Stake signing key (optional)"
          powers="stake registration + pool / DRep delegation: leave empty for an enterprise (payment-only) wallet"
          kind="stake"
          :status="e.stake_skey"
          @test="testLoad(e, 'stake')"
        />
      </div>

      <div class="d-flex align-center mt-2" style="gap: 0.5rem;">
        <v-btn size="small" variant="outlined" prepend-icon="mdi-wallet-plus" :disabled="entries.length >= MAX_KEYS" @click="addEntry">Add wallet</v-btn>
        <v-spacer />
        <v-btn color="primary" :loading="saving" prepend-icon="mdi-content-save" @click="save">Save and validate</v-btn>
      </div>
      <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mt-3">{{ saveError }}</v-alert>
    </v-card-text>
  </v-card>

  <v-dialog v-model="qrEnlarged" max-width="640">
    <v-card><v-card-text class="d-flex flex-column align-center pa-6">
      <div class="bg-white pa-4" style="border-radius: 8px;"><img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 480px; height: 480px;" /></div>
      <div v-if="genResult && genResult.ur_fragments.length > 1" class="text-caption text-medium-emphasis mt-2">{{ qrIndex + 1 }} / {{ genResult.ur_fragments.length }}</div>
      <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="qrEnlarged = false">Shrink</v-btn>
    </v-card-text></v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import QRCode from 'qrcode'
import { QR_CYCLE_INTERVAL_MS } from '@wallet-tools/shared-frontend/constants/timings'
import { useNotificationStore } from '@wallet-tools/shared-frontend/stores/notification'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'
import KeyField from '../components/KeyField.vue'
import FileBrowserDialog from '../components/FileBrowserDialog.vue'

interface ValidationResult { status: 'missing' | 'valid' | 'wrong_role' | 'error'; message?: string }
interface WalletAddressInfo {
  base_address_bech32: string
  stake_address_bech32: string | null
  payment_keyhash_hex: string
  stake_keyhash_hex: string | null
}
interface WalletStatus {
  label: string
  payment_skey_path: string
  stake_skey_path: string
  payment_skey: ValidationResult
  stake_skey: ValidationResult
  wallet_address: WalletAddressInfo | null
}
interface SignerConfigResponse {
  saved: boolean
  paired: boolean
  pairing_fingerprint: string | null
  wallets: WalletStatus[]
}
interface GenerateOk {
  base_address: string
  stake_address: string
  payment_keyhash_hex: string
  stake_keyhash_hex: string
  payment_skey_path: string
  stake_skey_path: string
  ur_fragments: string[]
}
interface Entry {
  label: string
  payment_skey_path: string | null
  stake_skey_path: string | null
  payment_skey: ValidationResult
  stake_skey: ValidationResult
  wallet_address: WalletAddressInfo | null
}

const MAX_KEYS = 10
const notify = useNotificationStore()

const entries = ref<Entry[]>([])
const paired = ref(false)
const pairingFingerprint = ref<string | null>(null)
const saving = ref(false)
const saveError = ref<string | null>(null)
const loadError = ref<string | null>(null)

function emptyValidation(): ValidationResult { return { status: 'missing' } }

function entryFrom(w: WalletStatus): Entry {
  return {
    label: w.label,
    payment_skey_path: w.payment_skey_path || null,
    stake_skey_path: w.stake_skey_path || null,
    payment_skey: w.payment_skey,
    stake_skey: w.stake_skey,
    wallet_address: w.wallet_address,
  }
}

function apply(d: SignerConfigResponse) {
  entries.value = (d.wallets || []).map(entryFrom)
  paired.value = d.paired
  pairingFingerprint.value = d.pairing_fingerprint
}

function addEntry() {
  entries.value.push({
    label: '', payment_skey_path: null, stake_skey_path: null,
    payment_skey: emptyValidation(), stake_skey: emptyValidation(), wallet_address: null,
  })
}
function remove(i: number) { entries.value.splice(i, 1) }

async function loadConfig() {
  try {
    const r = await fetch('/api/signer-config')
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    apply(await r.json())
  } catch (e: unknown) {
    loadError.value = e instanceof Error ? e.message : String(e)
  }
}

async function testLoad(entry: Entry, kind: 'payment' | 'stake') {
  const path = kind === 'payment' ? entry.payment_skey_path : entry.stake_skey_path
  const set = (v: ValidationResult) => { if (kind === 'payment') entry.payment_skey = v; else entry.stake_skey = v }
  if (!path || !path.trim()) { set({ status: 'missing' }); return }
  try {
    const r = await fetch('/api/test-load', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, path }),
    })
    if (!r.ok) { set({ status: 'error', message: `HTTP ${r.status}` }); return }
    set(await r.json())
  } catch (e: unknown) {
    set({ status: 'error', message: e instanceof Error ? e.message : String(e) })
  }
}

async function save() {
  saving.value = true
  saveError.value = null
  try {
    const keys = entries.value.map((e) => ({
      label: e.label.trim(),
      payment_skey_path: (e.payment_skey_path || '').trim(),
      stake_skey_path: (e.stake_skey_path || '').trim(),
    }))
    const r = await fetch('/api/signer-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keys }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message || `HTTP ${r.status}`)
    }
    apply(await r.json())
    notify.success('Signer config saved and validated')
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

// --- Wallet key generation (air-gapped) ---
const genLabel = ref('')
const genDir = ref('')
const generating = ref(false)
const genError = ref<string | null>(null)
const genResult = ref<GenerateOk | null>(null)
const genBrowseOpen = ref(false)
const qrEnlarged = ref(false)
const qrIndex = ref(0)
const qrDataUrl = ref<string | null>(null)
let qrTimer: ReturnType<typeof setInterval> | null = null

async function generateKeys() {
  generating.value = true
  genError.value = null
  genResult.value = null
  stopQrCycle()
  try {
    const r = await fetch('/api/generate-wallet-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ output_dir: genDir.value.trim() }),
    })
    const d = await r.json()
    if (d.status === 'error') { genError.value = d.message; return }
    genResult.value = d
    qrIndex.value = 0
    await renderCurrentFrame()
    startQrCycle()
    notify.success('Wallet keys generated on this machine')
    const e: Entry = {
      label: genLabel.value.trim() || `Wallet ${entries.value.length + 1}`,
      payment_skey_path: d.payment_skey_path,
      stake_skey_path: d.stake_skey_path,
      payment_skey: emptyValidation(),
      stake_skey: emptyValidation(),
      wallet_address: null,
    }
    entries.value.push(e)
    genLabel.value = ''
    // Persist immediately: an operator who exports the address and walks away
    // before clicking "Save and validate" would otherwise leave the signer
    // config without the new key paths: the first signing request for this
    // wallet would then fail.
    await save()
    if (saveError.value) {
      genError.value =
        'Keys were written to disk but NOT saved to the signer config: fix the wallet list below and click "Save and validate".'
      await testLoad(e, 'payment')
      await testLoad(e, 'stake')
    }
  } catch (e: unknown) {
    genError.value = e instanceof Error ? e.message : String(e)
  } finally {
    generating.value = false
  }
}

async function renderCurrentFrame() {
  if (!genResult.value || !genResult.value.ur_fragments.length) return
  const fragment = genResult.value.ur_fragments[qrIndex.value]
  qrDataUrl.value = await QRCode.toDataURL(fragment, { margin: 1, width: 800, errorCorrectionLevel: 'M' })
}

function startQrCycle() {
  stopQrCycle()
  if (!genResult.value || genResult.value.ur_fragments.length <= 1) return
  qrTimer = setInterval(async () => {
    qrIndex.value = (qrIndex.value + 1) % (genResult.value?.ur_fragments.length ?? 1)
    await renderCurrentFrame()
  }, QR_CYCLE_INTERVAL_MS)
}

function stopQrCycle() {
  if (qrTimer) clearInterval(qrTimer)
  qrTimer = null
}

async function copyExportUr() {
  if (!genResult.value) return
  await copyText(genResult.value.ur_fragments.join('\n'), 'Export UR fragments')
}

async function copyText(text: string, label = 'Value') {
  try {
    await navigator.clipboard.writeText(text)
    notify.success(`${label} copied to clipboard`)
  } catch {
    notify.error('Could not copy')
  }
}

onMounted(loadConfig)
onUnmounted(stopQrCycle)
</script>

<style scoped>
.wallet-entry { border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 1rem; margin-bottom: 1rem; }
.wallet-entry:first-of-type { border-top: none; padding-top: 0; }
.ur-list { border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; background: rgba(0,0,0,0.25); max-height: 220px; overflow-y: auto; padding: 0.3rem; }
.ur-row { font-family: monospace; font-size: 0.7rem; word-break: break-all; padding: 0.1rem 0.3rem; color: rgba(255,255,255,0.6); }
.ur-active { color: var(--wallet-gold, #FFD700); }
</style>
