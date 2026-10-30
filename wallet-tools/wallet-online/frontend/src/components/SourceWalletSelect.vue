<template>
  <v-select
    v-if="wallets.length > 1"
    :model-value="modelValue"
    :items="items"
    item-title="title"
    item-value="value"
    label="From wallet"
    density="compact"
    variant="outlined"
    hide-details
    prepend-inner-icon="mdi-wallet"
    @update:model-value="onSelect"
  />
  <div v-else-if="wallets.length === 1" class="text-caption text-medium-emphasis">
    From wallet <strong class="text-gold">{{ wallets[0].label }}</strong>:
    <code>{{ short(wallets[0].address) }}</code>
  </div>
  <div v-else-if="delegatableOnly && loaded" class="text-caption text-medium-emphasis">
    <v-icon size="14" class="me-1">mdi-information-outline</v-icon>
    No staking-capable wallet: enterprise (addr1v…) addresses cannot delegate.
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

interface OwnWallet { label: string; address: string }
interface BookEntry { label: string; address: string; kind: string; stake_address: string | null }

const props = withDefaults(
  defineProps<{ modelValue: string | null; delegatableOnly?: boolean }>(),
  { delegatableOnly: false },
)
const emit = defineEmits<{
  'update:modelValue': [value: string | null]
  change: [value: string | null]
}>()

const wallets = ref<OwnWallet[]>([])
const loaded = ref(false)

const items = computed(() =>
  wallets.value.map((w) => ({ title: `${w.label}, ${short(w.address)}`, value: w.address })),
)

function short(a: string): string {
  return a.length > 26 ? `${a.slice(0, 15)}…${a.slice(-8)}` : a
}

function onSelect(v: string | null) {
  emit('update:modelValue', v)
  emit('change', v)
}

async function load() {
  try {
    const r = await fetch('/api/wallet-config')
    if (!r.ok) { emit('change', props.modelValue); return }
    const d = await r.json()
    wallets.value = (d.address_book || [])
      .filter((e: BookEntry) => e.kind === 'own')
      // Delegation needs a stake credential: exclude enterprise (no stake_address).
      .filter((e: BookEntry) => !props.delegatableOnly || !!e.stake_address)
      .map((e: BookEntry) => ({ label: e.label, address: e.address }))
    let sel = props.modelValue
    if (!sel || !wallets.value.some((w) => w.address === sel)) {
      sel = wallets.value.length ? wallets.value[0].address : null
    }
    emit('update:modelValue', sel)
    emit('change', sel)
  } catch {
    emit('change', props.modelValue)
  } finally {
    loaded.value = true
  }
}

onMounted(load)
</script>
