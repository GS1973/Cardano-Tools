<template>
  <v-card class="mb-4">
    <v-card-title>Setup</v-card-title>
  </v-card>

  <v-alert v-if="loadError" type="error" density="compact" variant="tonal" class="mb-4">{{ loadError }}</v-alert>

  <v-alert type="info" density="compact" variant="tonal" class="mb-4">
    v1.0 supports <code>cardano-cli</code> generated <code>.skey</code> files only.
    Mnemonic wallets: export once with <code>cardano-address</code> to skey format.
    Hardware wallets are not supported.
  </v-alert>

  <v-card>
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.75rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Signing keys</h3>
        <v-spacer />
        <v-btn
          v-if="locked"
          size="small"
          variant="outlined"
          prepend-icon="mdi-pencil"
          @click="enterEditMode"
        >Edit</v-btn>
      </div>

      <v-table v-if="locked" density="compact" class="mb-2">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 220px;">VRF signing key</td><td>{{ statusLabel(validation.vrf_skey) }}</td></tr>
          <tr><td class="text-medium-emphasis">Cold signing key</td><td>{{ statusLabel(validation.cold_skey) }}</td></tr>
          <tr><td class="text-medium-emphasis">Owner stake signing key</td><td>{{ statusLabel(validation.owner_skey) }}</td></tr>
          <tr><td class="text-medium-emphasis">Reward stake signing key</td><td>{{ statusLabel(validation.reward_skey) }}</td></tr>
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
        Key paths are not displayed. Click Edit to type new paths. Saving overwrites the stored values.
      </div>

      <template v-if="!locked">
        <KeyField
          v-model="cfg.vrf_skey"
          label="VRF signing key"
          powers="Leaderlog"
          kind="vrf"
          :status="validation.vrf_skey"
          @test="testLoad('vrf', cfg.vrf_skey, 'vrf_skey')"
        />

        <KeyField
          v-model="cfg.cold_skey"
          label="Cold signing key"
          powers="KES rotation, pool parameter updates"
          kind="cold"
          :status="validation.cold_skey"
          @test="testLoad('cold', cfg.cold_skey, 'cold_skey')"
        />

        <KeyField
          v-model="cfg.owner_skey"
          label="Owner stake signing key"
          powers="pool parameter updates"
          kind="stake"
          :status="validation.owner_skey"
          @test="testLoad('stake', cfg.owner_skey, 'owner_skey')"
        />

        <v-checkbox
          v-model="rewardSameAsOwner"
          label="Reward stake key is the same file as owner stake key"
          density="compact"
          hide-details
          class="mb-3"
        />

        <KeyField
          v-model="cfg.reward_skey"
          label="Reward stake signing key"
          powers="reward withdrawal"
          kind="stake"
          :readonly="rewardSameAsOwner"
          :status="validation.reward_skey"
          @test="testLoad('stake', cfg.reward_skey, 'reward_skey')"
        />

        <KeyField
          v-model="cfg.payment_skey"
          label="Payment signing key"
          powers="transaction fees"
          kind="payment"
          :status="validation.payment_skey"
          @test="testLoad('payment', cfg.payment_skey, 'payment_skey')"
        />

        <div class="d-flex justify-end mt-4" style="gap: 0.5rem;">
          <v-btn
            v-if="hadSavedConfig"
            variant="text"
            prepend-icon="mdi-close"
            @click="cancelEdit"
          >Cancel</v-btn>
          <v-btn
            color="primary"
            :loading="saving"
            prepend-icon="mdi-content-save"
            @click="save"
          >Save and validate</v-btn>
        </div>

        <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mt-3">{{ saveError }}</v-alert>
      </template>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import KeyField from '../components/KeyField.vue'

interface ValidationResult {
  status: 'missing' | 'valid' | 'wrong_role' | 'error'
  message?: string
}

interface SignerConfig {
  vrf_skey: string | null
  cold_skey: string | null
  owner_skey: string | null
  reward_skey: string | null
  payment_skey: string | null
}

interface ValidationByField {
  vrf_skey: ValidationResult
  cold_skey: ValidationResult
  owner_skey: ValidationResult
  reward_skey: ValidationResult
  payment_skey: ValidationResult
}

interface SignerConfigStatusResponse {
  saved: boolean
  paired: boolean
  pairing_fingerprint: string | null
  validation: ValidationByField
}

const notify = useNotificationStore()

const cfg = reactive<SignerConfig>({
  vrf_skey: null,
  cold_skey: null,
  owner_skey: null,
  reward_skey: null,
  payment_skey: null,
})

const validation = reactive<ValidationByField>({
  vrf_skey: { status: 'missing' },
  cold_skey: { status: 'missing' },
  owner_skey: { status: 'missing' },
  reward_skey: { status: 'missing' },
  payment_skey: { status: 'missing' },
})

const locked = ref(false)
const hadSavedConfig = ref(false)
const paired = ref(false)
const pairingFingerprint = ref<string | null>(null)

const saving = ref(false)
const saveError = ref<string | null>(null)
const loadError = ref<string | null>(null)
const rewardSameAsOwner = ref(true)

// While the checkbox is on, mirror owner -> reward in both the form value
// and its validation status (so a re-validated owner immediately updates
// the reward bulb without waiting for save).
watch([rewardSameAsOwner, () => cfg.owner_skey], ([same, owner]) => {
  if (same) {
    cfg.reward_skey = owner
    validation.reward_skey = { ...validation.owner_skey }
  }
})
watch(() => ({ ...validation.owner_skey }), (status) => {
  if (rewardSameAsOwner.value) {
    validation.reward_skey = { ...status }
  }
}, { deep: true })

function clearForm() {
  cfg.vrf_skey = null
  cfg.cold_skey = null
  cfg.owner_skey = null
  cfg.reward_skey = null
  cfg.payment_skey = null
  rewardSameAsOwner.value = true
  validation.vrf_skey = { status: 'missing' }
  validation.cold_skey = { status: 'missing' }
  validation.owner_skey = { status: 'missing' }
  validation.reward_skey = { status: 'missing' }
  validation.payment_skey = { status: 'missing' }
  saveError.value = null
}

function applyStatus(d: SignerConfigStatusResponse) {
  Object.assign(validation, d.validation)
  locked.value = d.saved
  hadSavedConfig.value = d.saved
  paired.value = d.paired
  pairingFingerprint.value = d.pairing_fingerprint
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
    const d: SignerConfigStatusResponse = await r.json()
    applyStatus(d)
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
  if (hadSavedConfig.value) {
    locked.value = true
    void loadConfig()
  }
}

async function save() {
  saving.value = true
  saveError.value = null
  if (rewardSameAsOwner.value) cfg.reward_skey = cfg.owner_skey
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
    const d: SignerConfigStatusResponse = await r.json()
    // Clear the form inputs first (paths are not shown once locked), then
    // apply the server's re-validated status: doing it the other way round
    // wipes the just-validated bulbs back to "missing".
    clearForm()
    applyStatus(d)
    notify.success('Signer config saved and validated')
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

onMounted(loadConfig)
</script>
