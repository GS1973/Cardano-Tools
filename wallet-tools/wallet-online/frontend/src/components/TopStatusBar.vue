<template>
  <header class="drep-topbar">
    <div class="brand">
      <v-icon icon="mdi-wallet" size="20" class="brand-icon" />
      <span class="brand-name">Wallet&nbsp;Tools</span>
      <span class="brand-sub">online</span>
    </div>
    <v-spacer />
    <span class="version">{{ VERSION }}</span>
  </header>
</template>

<script setup lang="ts">
const VERSION = `v${__APP_VERSION__}`
</script>

<style scoped>
.drep-topbar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 56px;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0 24px;
  background: #16161f;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  z-index: 1005;
}
.brand {
  display: flex;
  align-items: baseline;
  gap: 0.4rem;
}
.brand-icon {
  color: var(--wallet-gold, #FFD700);
  align-self: center;
}
.brand-name {
  font-weight: 600;
  letter-spacing: 0.02em;
  color: #fff;
}
.brand-sub {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: rgba(255, 255, 255, 0.4);
}
.version {
  font-size: 0.8125rem;
  color: rgba(255, 255, 255, 0.45);
}
</style>
