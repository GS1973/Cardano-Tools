<template>
  <div>
  <v-card class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">{{ title }}</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        <slot>
          Either scan the QR with the signer or copy the UR fragments and paste them into the signer.
        </slot>
      </p>
      <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
        <div class="d-flex flex-column align-center" style="flex: 0 0 auto;">
          <div class="bg-white pa-2 d-flex align-center justify-center" style="border-radius: 8px;">
            <img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 160px; height: 160px;" />
          </div>
          <v-btn class="mt-2" size="small" variant="text" prepend-icon="mdi-arrow-expand" @click="enlarged = true">Enlarge</v-btn>
        </div>
        <div style="flex: 1 1 auto; min-width: 0;">
          <div class="d-flex align-center justify-end mb-1" style="gap: 0.75rem;">
            <span v-if="qrFragments.length > 1" class="text-caption text-medium-emphasis">
              {{ qrIndex + 1 }} / {{ qrFragments.length }}
            </span>
            <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="$emit('copy')">Copy</v-btn>
          </div>
          <div class="ur-list">
            <div
              v-for="(f, i) in qrFragments"
              :key="i"
              :class="['ur-row', { 'ur-active': i === qrIndex }]"
            >{{ f }}</div>
          </div>
          <RequestFingerprintBadge :fingerprint="fingerprint" />
        </div>
      </div>
    </v-card-text>
  </v-card>

  <v-dialog v-model="enlarged" max-width="640">
    <v-card>
      <v-card-text class="d-flex flex-column align-center pa-6">
        <div class="bg-white pa-4" style="border-radius: 8px;">
          <img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 480px; height: 480px;" />
        </div>
        <div class="text-caption text-medium-emphasis mt-2">{{ qrIndex + 1 }} / {{ qrFragments.length }}</div>
        <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="enlarged = false">Shrink</v-btn>
      </v-card-text>
    </v-card>
  </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import RequestFingerprintBadge from './RequestFingerprintBadge.vue'

withDefaults(
  defineProps<{
    qrDataUrl: string | null
    qrFragments: string[]
    qrIndex: number
    fingerprint: string | null
    title?: string
  }>(),
  {
    title: 'Request',
  },
)

defineEmits<{
  (e: 'copy'): void
}>()

const enlarged = ref(false)
</script>
