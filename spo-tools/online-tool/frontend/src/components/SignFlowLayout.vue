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
 * Common page shell for the operational sign-flow views (Withdraw,
 * DRep, PoolParams). Renders the title card, then routes to either
 * the NotConfigured / NotPaired prompts or to the per-view content
 * via the default slot. KESRotationView intentionally does not use
 * this layout because its initial-bootstrap and opcert-status
 * sections do not fit the same shape.
 */
import NotConfiguredCard from './NotConfiguredCard.vue'
import NotPairedCard from './NotPairedCard.vue'

defineProps<{
  title: string
  notConfigured: boolean
  notPaired: boolean
}>()
</script>
