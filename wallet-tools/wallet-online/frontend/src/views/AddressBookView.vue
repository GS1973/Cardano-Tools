<template>
  <v-card class="mb-4"><v-card-title>Address book</v-card-title></v-card>

  <NotPairedCard v-if="notPaired" />

  <template v-else>
    <v-card class="mb-4">
      <v-card-text>
        <p class="text-caption text-medium-emphasis mb-0">
          <strong class="text-gold">Own</strong> wallets are signable: their keys live on the air-gapped signer, and they are the
          source a payment or delegation funds from (max {{ MAX_OWN }}).
          <strong>External</strong> entries are destinations only: addresses you send to.
          Picking a verified label here instead of pasting an address protects against clipboard-swapping malware.
        </p>
      </v-card-text>
    </v-card>

    <v-card>
      <v-card-text>
        <div v-if="!entries.length" class="text-medium-emphasis text-body-2 mb-3">
          No addresses yet. Add one of your own wallets (import it under <strong>New address</strong> first, or paste its base address) or an external destination.
        </div>

        <div v-for="(e, i) in entries" :key="i" class="ab-row mb-2">
          <v-text-field
            v-model="e.label" label="Label" density="compact" variant="outlined" hide-details
            placeholder="e.g. BKIND pledge"
          />
          <v-text-field
            v-model="e.address" label="Address (addr1…)" density="compact" variant="outlined" hide-details
            placeholder="addr1…"
          />
          <v-chip
            size="small" variant="tonal" :color="e.kind === 'own' ? 'primary' : undefined"
            :prepend-icon="e.kind === 'own' ? 'mdi-wallet' : 'mdi-send'"
          >{{ e.kind === 'own' ? 'Own' : 'External' }}</v-chip>
          <v-btn size="small" variant="text" icon="mdi-delete" @click="remove(i)" />
        </div>

        <div class="d-flex align-center mt-3" style="gap: 0.5rem;">
          <v-btn size="small" variant="outlined" prepend-icon="mdi-wallet-plus" :disabled="ownCount >= MAX_OWN" @click="add('own')">
            Add own wallet
          </v-btn>
          <v-btn size="small" variant="outlined" prepend-icon="mdi-plus" @click="add('external')">
            Add destination
          </v-btn>
          <v-spacer />
          <span class="text-caption text-medium-emphasis">{{ ownCount }} / {{ MAX_OWN }} own</span>
          <v-btn color="primary" :loading="saving" prepend-icon="mdi-content-save" @click="save">Save</v-btn>
        </div>

        <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mt-3">{{ saveError }}</v-alert>
      </v-card-text>
    </v-card>
  </template>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useNotificationStore } from '@wallet-tools/shared-frontend/stores/notification'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'
import NotPairedCard from '../components/NotPairedCard.vue'

type Kind = 'own' | 'external'
interface Entry { label: string; address: string; kind: Kind }

const MAX_OWN = 10
const notify = useNotificationStore()

const entries = ref<Entry[]>([])
const saving = ref(false)
const saveError = ref<string | null>(null)
const notPaired = ref(false)

const ownCount = computed(() => entries.value.filter((e) => e.kind === 'own').length)

function add(kind: Kind) {
  entries.value.push({ label: '', address: '', kind })
}
function remove(i: number) {
  entries.value.splice(i, 1)
}

async function load() {
  try {
    const r = await fetch('/api/wallet-config')
    if (!r.ok) return
    const d = await r.json()
    notPaired.value = !d.paired
    entries.value = (d.address_book || []).map((e: Entry) => ({ label: e.label, address: e.address, kind: e.kind }))
  } catch { /* transient */ }
}

async function save() {
  saving.value = true
  saveError.value = null
  try {
    const payload = entries.value.map((e) => ({
      label: e.label.trim(),
      address: e.address.trim(),
      kind: e.kind,
    }))
    const r = await fetch('/api/address-book', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries: payload }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message)
    }
    const d = await r.json()
    entries.value = (d.address_book || []).map((e: Entry) => ({ label: e.label, address: e.address, kind: e.kind }))
    notify.success('Address book saved')
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.ab-row {
  display: grid;
  grid-template-columns: 1fr 2fr auto auto;
  gap: 0.6rem;
  align-items: center;
}
</style>
