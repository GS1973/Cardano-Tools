<template>
  <div v-if="fingerprint" class="fp-row">
    <span class="fp-label">Request fingerprint</span>
    <code class="fp-value">{{ fingerprint }}</code>
  </div>
</template>

<script setup lang="ts">
defineProps<{ fingerprint: string | null }>()
</script>

<style scoped>
.fp-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.5rem;
  padding: 0.4rem 0.6rem;
  background: rgba(255, 215, 0, 0.06);
  border: 1px solid rgba(255, 215, 0, 0.2);
  border-radius: 6px;
}
.fp-label {
  font-size: 0.78rem;
  color: var(--drep-gold);
  font-weight: 700;
  letter-spacing: 0.04em;
}
.fp-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 1rem;
  letter-spacing: 0.06em;
}
</style>
