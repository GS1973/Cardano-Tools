<template>
  <v-card class="mb-4">
    <v-card-title>{{ title }}</v-card-title>
  </v-card>
  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />
  <template v-else>
    <slot />
  </template>
</template>

<script setup lang="ts">
/**
 * Common page shell for the operational DRep views. Renders the title
 * card, then routes to the NotConfigured / NotPaired prompts or to the
 * per-view content via the default slot.
 */
import NotConfiguredCard from './NotConfiguredCard.vue'
import NotPairedCard from './NotPairedCard.vue'

defineProps<{
  title: string
  notConfigured: boolean
  notPaired: boolean
}>()
</script>
