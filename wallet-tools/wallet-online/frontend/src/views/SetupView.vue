<template>
  <v-card class="mb-4"><v-card-title>Setup</v-card-title></v-card>
  <v-card>
    <v-card-text>
      <p class="text-caption text-medium-emphasis mb-4">
        Public configuration only: no private keys. Your wallet and destination addresses live in the
        <router-link to="/address-book" class="text-gold">Address book</router-link>. The signing keys live on the air-gapped signer.
        The only thing stored here is an optional Koios API key for chain access.
      </p>

      <v-text-field
        v-model="koiosApiKey"
        label="Koios API key (optional)"
        placeholder="leave blank for public rate limits"
        type="password" density="compact" variant="outlined"
        :hint="hasKoiosKey ? 'A key is stored. Leave blank to keep it. Type a new one to replace.' : 'Optional: raises Koios rate limits. Leave blank to use the public tier.'"
        persistent-hint class="mb-4"
      />

      <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mb-3">{{ saveError }}</v-alert>

      <div class="d-flex align-center" style="gap: 1rem;">
        <v-btn color="primary" :loading="saving" prepend-icon="mdi-content-save" @click="save">Save</v-btn>
        <v-chip v-if="saved" color="success" size="small" variant="tonal" prepend-icon="mdi-check">{{ ownCount }} wallet(s) configured</v-chip>
        <v-chip v-else size="small" variant="tonal" color="warning" prepend-icon="mdi-wallet-outline">No wallet yet: add one in the Address book</v-chip>
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
import { useNotificationStore } from '@wallet-tools/shared-frontend/stores/notification'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'

interface AddressEntryView { label: string; address: string; kind: string; stake_address: string | null }

const notify = useNotificationStore()
const koiosApiKey = ref('')
const saved = ref(false)
const paired = ref(false)
const pairingFingerprint = ref<string | null>(null)
const hasKoiosKey = ref(false)
const ownCount = ref(0)
const saving = ref(false)
const saveError = ref<string | null>(null)

function apply(d: {
  saved: boolean
  paired: boolean
  pairing_fingerprint: string | null
  has_koios_api_key: boolean
  address_book: AddressEntryView[]
}) {
  saved.value = d.saved
  paired.value = d.paired
  pairingFingerprint.value = d.pairing_fingerprint
  hasKoiosKey.value = d.has_koios_api_key
  ownCount.value = (d.address_book || []).filter((e) => e.kind === 'own').length
}

async function load() {
  try {
    const r = await fetch('/api/wallet-config')
    if (!r.ok) return
    apply(await r.json())
  } catch { /* leave defaults */ }
}

async function save() {
  saving.value = true
  saveError.value = null
  try {
    const r = await fetch('/api/wallet-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ koios_api_key: koiosApiKey.value.trim() || null }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      saveError.value = err.message
      return
    }
    apply(await r.json())
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
