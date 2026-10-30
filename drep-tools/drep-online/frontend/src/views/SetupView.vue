<template>
  <v-card class="mb-4"><v-card-title>Setup</v-card-title></v-card>
  <v-card>
    <v-card-text>
      <p class="text-caption text-medium-emphasis mb-4">Public configuration only: no private keys. The DRep + payment signing keys live on the air-gapped signer.</p>

      <v-text-field
        v-model="drepId"
        label="DRep id (drep1…): optional"
        placeholder="drep1… (CIP-105 or CIP-129)"
        density="compact" variant="outlined"
        hint="Optional: leave blank for now and add it once the signer has generated your DRep key. Required before you can register, vote, update, or retire."
        persistent-hint
        :error-messages="drepIdError" class="mb-4"
      />
      <v-text-field
        v-model="paymentAddress"
        label="Payment address (addr1…)"
        placeholder="addr1…: funds fees + the registration deposit"
        density="compact" variant="outlined"
        :error-messages="paymentError" class="mb-2"
      />
      <v-text-field
        v-model="koiosApiKey"
        label="Koios API key (optional)"
        placeholder="leave blank for public rate limits"
        type="password" density="compact" variant="outlined"
        :hint="hasKoiosKey ? 'A key is stored. Leave blank to keep it. Type a new one to replace.' : ''"
        persistent-hint class="mb-4"
      />
      <v-text-field
        v-model="manifestBaseUrl"
        label="Manifest base URL (optional)"
        placeholder="https://your-domain.example/governance/"
        density="compact" variant="outlined"
        hint="Where you host your DRep manifest documents, over https. Register/Update then only ask for the file name and can compute the hash for you."
        persistent-hint class="mb-4"
      />

      <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mb-3">{{ saveError }}</v-alert>

      <div class="d-flex align-center" style="gap: 1rem;">
        <v-btn color="primary" :loading="saving" prepend-icon="mdi-content-save" @click="save">Save</v-btn>
        <v-chip v-if="saved" color="success" size="small" variant="tonal" prepend-icon="mdi-check">Configured</v-chip>
        <v-spacer />
        <v-chip :color="paired ? 'success' : 'warning'" size="small" variant="tonal" :prepend-icon="paired ? 'mdi-shield-check' : 'mdi-shield-alert'">
          {{ paired ? `Paired ${pairingFingerprint ?? ''}` : 'Not paired' }}
        </v-chip>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@drep-tools/shared-frontend/types/errors'

const notify = useNotificationStore()
const drepId = ref('')
const paymentAddress = ref('')
const koiosApiKey = ref('')
const manifestBaseUrl = ref('')
const saved = ref(false)
const paired = ref(false)
const pairingFingerprint = ref<string | null>(null)
const hasKoiosKey = ref(false)
const saving = ref(false)
const saveError = ref<string | null>(null)
const drepIdError = ref<string[]>([])
const paymentError = ref<string[]>([])

async function load() {
  try {
    const r = await fetch('/api/drep-config')
    if (!r.ok) return
    const d = await r.json()
    drepId.value = d.drep_id || ''
    paymentAddress.value = d.payment_address || ''
    manifestBaseUrl.value = d.manifest_base_url || ''
    saved.value = d.saved
    paired.value = d.paired
    pairingFingerprint.value = d.pairing_fingerprint
    hasKoiosKey.value = d.has_koios_api_key
  } catch { /* leave defaults */ }
}

async function save() {
  saving.value = true
  saveError.value = null
  drepIdError.value = []
  paymentError.value = []
  try {
    const r = await fetch('/api/drep-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drep_id: drepId.value.trim(),
        payment_address: paymentAddress.value.trim(),
        koios_api_key: koiosApiKey.value.trim() || null,
        manifest_base_url: manifestBaseUrl.value.trim() || null,
      }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      const m = err.message.toLowerCase()
      if (m.includes('drep')) drepIdError.value = [err.message]
      else if (m.includes('payment')) paymentError.value = [err.message]
      else saveError.value = err.message
      return
    }
    const d = await r.json()
    saved.value = d.saved
    paired.value = d.paired
    pairingFingerprint.value = d.pairing_fingerprint
    hasKoiosKey.value = d.has_koios_api_key
    koiosApiKey.value = ''
    notify.success('Configuration saved')
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>
