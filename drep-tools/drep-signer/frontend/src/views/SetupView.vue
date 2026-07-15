<template>
  <v-card class="mb-4"><v-card-title>Setup</v-card-title></v-card>

  <v-alert v-if="loadError" type="error" density="compact" variant="tonal" class="mb-4">{{ loadError }}</v-alert>

  <v-alert type="info" density="compact" variant="tonal" class="mb-4">
    v1.0 supports <code>cardano-cli</code> generated <code>.skey</code> files only.
    Mnemonic wallets: export once with <code>cardano-address</code> to skey format.
    This signer holds <strong>only</strong> the DRep key and a payment key — never the pool cold key.
  </v-alert>

  <v-card class="mb-4">
    <v-card-text>
      <div class="d-flex align-center mb-2" style="gap: 0.75rem;">
        <v-icon icon="mdi-key-plus" />
        <h3 class="text-subtitle-1 mt-0 mb-0">Generate a new DRep key</h3>
      </div>
      <p class="text-caption text-medium-emphasis mb-3">
        Creates a fresh Ed25519 DRep key pair on this air-gapped machine and writes
        <code>drep.skey</code> + <code>drep.vkey</code> to the chosen directory. Pick a folder on
        your encrypted removable drive — the key never leaves this machine. Skip this if you
        already generated a key (with cardano-cli, or derived from your wallet mnemonic).
      </p>
      <div class="d-flex align-start" style="gap: 0.5rem;">
        <v-text-field
          v-model="genDir"
          label="Output directory (under /media, /mnt or /run/media)"
          placeholder="/media/usb/keys"
          density="compact" variant="outlined" hide-details
        />
        <v-btn size="small" variant="outlined" prepend-icon="mdi-folder-open" class="mt-1" @click="genBrowseOpen = true">Browse</v-btn>
        <v-btn color="primary" :loading="generating" :disabled="!genDir.trim()" prepend-icon="mdi-key-plus" class="mt-1" @click="generateKey">Generate</v-btn>
      </div>
      <v-alert v-if="genError" type="error" density="compact" variant="tonal" class="mt-3">{{ genError }}</v-alert>
      <v-alert v-if="genResult" type="success" density="compact" variant="tonal" class="mt-3">
        <div class="mb-1"><strong>DRep key generated.</strong> Your DRep id — carry this to the online tool's Setup:</div>
        <div class="d-flex align-center" style="gap: 0.5rem;">
          <code class="text-caption" style="word-break: break-all;">{{ genResult.drep_id }}</code>
          <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyDrepId">Copy</v-btn>
        </div>
        <div class="text-caption mt-1">Signing key written to <code>{{ genResult.skey_path }}</code> and filled in below.</div>
        <div v-if="paymentAtRisk" class="text-caption mt-1">
          <strong>Re-enter the payment signing key path below before saving</strong> — saved paths are never displayed, so it could not be pre-filled.
        </div>
      </v-alert>
      <FileBrowserDialog v-model="genBrowseOpen" title="Select output directory" :initial-path="genDir || null" select-dir @pick="(p) => { genDir = p }" />
    </v-card-text>
  </v-card>

  <v-card>
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.75rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Signing keys</h3>
        <v-spacer />
        <v-btn v-if="locked" size="small" variant="outlined" prepend-icon="mdi-pencil" @click="enterEditMode">Edit</v-btn>
      </div>

      <v-table v-if="locked" density="compact" class="mb-2">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 220px;">DRep signing key</td><td>{{ statusLabel(validation.drep_skey) }}</td></tr>
          <tr v-if="drepId">
            <td class="text-medium-emphasis">DRep ID</td>
            <td>
              <div class="d-flex align-center" style="gap: 0.5rem;">
                <code class="text-caption" style="word-break: break-all;">{{ drepId.cip129 }}</code>
                <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyText(drepId.cip129, 'DRep ID')">Copy</v-btn>
              </div>
              <div class="text-caption text-medium-emphasis mt-1">CIP-105: <code style="word-break: break-all;">{{ drepId.cip105 }}</code></div>
            </td>
          </tr>
          <tr><td class="text-medium-emphasis">Payment signing key</td><td>{{ statusLabel(validation.payment_skey) }}</td></tr>
          <tr>
            <td class="text-medium-emphasis">Paired with online tool</td>
            <td>
              <span v-if="paired"><code class="text-caption">{{ pairingFingerprint }}</code></span>
              <span v-else class="text-medium-emphasis">not paired</span>
            </td>
          </tr>
        </tbody>
      </v-table>
      <div v-if="locked" class="text-caption text-medium-emphasis">
        Key paths are not displayed. Click Edit to type new paths; saving overwrites the stored values.
      </div>

      <template v-if="!locked">
        <KeyField
          v-model="cfg.drep_skey"
          label="DRep signing key"
          powers="DRep registration, update, retirement, votes"
          kind="drep"
          :status="validation.drep_skey"
          @test="testLoad('drep', cfg.drep_skey, 'drep_skey')"
        />
        <KeyField
          v-model="cfg.payment_skey"
          label="Payment signing key"
          powers="transaction fees + the registration deposit"
          kind="payment"
          :status="validation.payment_skey"
          @test="testLoad('payment', cfg.payment_skey, 'payment_skey')"
        />

        <div class="d-flex justify-end mt-4" style="gap: 0.5rem;">
          <v-btn v-if="hadSavedConfig" variant="text" prepend-icon="mdi-close" @click="cancelEdit">Cancel</v-btn>
          <v-btn color="primary" :loading="saving" prepend-icon="mdi-content-save" @click="save">Save and validate</v-btn>
        </div>
        <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mt-3">{{ saveError }}</v-alert>
      </template>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import KeyField from '../components/KeyField.vue'
import FileBrowserDialog from '../components/FileBrowserDialog.vue'

interface ValidationResult {
  status: 'missing' | 'valid' | 'wrong_role' | 'error'
  message?: string
}
interface SignerConfig {
  drep_skey: string | null
  payment_skey: string | null
}
interface ValidationByField {
  drep_skey: ValidationResult
  payment_skey: ValidationResult
}
interface DRepIdInfo {
  cip129: string
  cip105: string
  keyhash_hex: string
}
interface SignerConfigStatusResponse {
  saved: boolean
  paired: boolean
  pairing_fingerprint: string | null
  validation: ValidationByField
  drep_id: DRepIdInfo | null
}

const notify = useNotificationStore()

const cfg = reactive<SignerConfig>({ drep_skey: null, payment_skey: null })
const validation = reactive<ValidationByField>({
  drep_skey: { status: 'missing' },
  payment_skey: { status: 'missing' },
})
const locked = ref(false)
const hadSavedConfig = ref(false)
const paired = ref(false)
const pairingFingerprint = ref<string | null>(null)
const drepId = ref<DRepIdInfo | null>(null)
const saving = ref(false)
const saveError = ref<string | null>(null)
const loadError = ref<string | null>(null)

function clearForm() {
  cfg.drep_skey = null
  cfg.payment_skey = null
  validation.drep_skey = { status: 'missing' }
  validation.payment_skey = { status: 'missing' }
  saveError.value = null
}

function applyStatus(d: SignerConfigStatusResponse) {
  Object.assign(validation, d.validation)
  locked.value = d.saved
  hadSavedConfig.value = d.saved
  paired.value = d.paired
  pairingFingerprint.value = d.pairing_fingerprint
  drepId.value = d.drep_id
}

function statusLabel(v: ValidationResult): string {
  switch (v.status) {
    case 'valid': return 'valid'
    case 'missing': return 'not configured'
    case 'wrong_role': return 'wrong role (this file is not the kind expected for this field)'
    case 'error': return v.message ? `error: ${v.message}` : 'error'
  }
}

async function loadConfig() {
  try {
    const r = await fetch('/api/signer-config')
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    applyStatus(await r.json())
  } catch (e: unknown) {
    loadError.value = e instanceof Error ? e.message : String(e)
  }
}

async function testLoad(kind: string, path: string | null, field: keyof ValidationByField) {
  if (!path || !path.trim()) {
    validation[field] = { status: 'missing' }
    return
  }
  try {
    const r = await fetch('/api/test-load', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, path }),
    })
    if (!r.ok) {
      validation[field] = { status: 'error', message: `HTTP ${r.status}` }
      return
    }
    validation[field] = await r.json()
  } catch (e: unknown) {
    validation[field] = { status: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}

function enterEditMode() {
  clearForm()
  locked.value = false
}
function cancelEdit() {
  clearForm()
  paymentAtRisk.value = false
  if (hadSavedConfig.value) {
    locked.value = true
    void loadConfig()
  }
}

async function save() {
  // A keygen-initiated edit cleared the redacted payment path; POSTing a
  // null now would unconfigure the previously configured payment key path.
  if (paymentAtRisk.value && !cfg.payment_skey?.trim()) {
    saveError.value =
      'Payment signing key is empty: saving now would unconfigure the previously configured payment key path. Re-enter its path (saved paths are never displayed).'
    return
  }
  saving.value = true
  saveError.value = null
  try {
    const r = await fetch('/api/signer-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message || `HTTP ${r.status}`)
    }
    const d = await r.json()
    // Clear the form inputs first (paths are not shown once locked), then
    // apply the server's re-validated status — doing it the other way round
    // wipes the just-validated bulbs back to "missing".
    clearForm()
    applyStatus(d)
    paymentAtRisk.value = false
    notify.success('Signer config saved and validated')
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

// --- DRep key generation (air-gapped) ---
const genDir = ref('')
const generating = ref(false)
const genError = ref<string | null>(null)
const genResult = ref<{ drep_id: string; drep_id_legacy: string; skey_path: string; vkey_path: string } | null>(null)
const genBrowseOpen = ref(false)
// True while an edit session started by keygen would overwrite a previously
// configured payment key path (valid or not — the file may merely be
// unreadable right now) that the form cannot repopulate because it is redacted.
const paymentAtRisk = ref(false)

async function generateKey() {
  generating.value = true
  genError.value = null
  genResult.value = null
  try {
    const r = await fetch('/api/generate-drep-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ output_dir: genDir.value.trim() }),
    })
    const d = await r.json()
    if (d.status === 'error') { genError.value = d.message; return }
    genResult.value = d
    notify.success('DRep key generated on this machine')
    // Land the new path in the key form (unlock first if already saved).
    // Saved key paths are redacted, so unlocking cannot repopulate the
    // payment path — remember it was configured so save() refuses to
    // silently wipe it with a null.
    if (locked.value) {
      // 'missing' is the only status meaning no path is saved; a path in
      // 'error' (e.g. key USB not mounted right now) or 'wrong_role' state
      // is still configuration the operator must not lose silently.
      paymentAtRisk.value = validation.payment_skey.status !== 'missing'
      enterEditMode()
    }
    cfg.drep_skey = d.skey_path
    await testLoad('drep', cfg.drep_skey, 'drep_skey')
  } catch (e: unknown) {
    genError.value = e instanceof Error ? e.message : String(e)
  } finally {
    generating.value = false
  }
}

async function copyText(text: string, label = 'Value') {
  try {
    await navigator.clipboard.writeText(text)
    notify.success(`${label} copied to clipboard`)
  } catch {
    notify.error('Could not copy')
  }
}

async function copyDrepId() {
  if (genResult.value) await copyText(genResult.value.drep_id, 'DRep id')
}

onMounted(loadConfig)
</script>
