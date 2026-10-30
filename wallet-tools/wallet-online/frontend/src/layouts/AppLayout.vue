<template>
  <TopStatusBar />

  <v-navigation-drawer permanent width="260" color="secondary" rounded="lg" class="drep-drawer" style="top: 72px !important; bottom: 24px !important; height: auto !important; margin-left: 24px !important;">
    <v-list density="compact" nav class="pt-3">
      <v-list-item
        v-for="route in navRoutes"
        :key="route.path"
        :to="route.path"
        :prepend-icon="route.meta?.icon as string"
        :title="route.meta?.title as string"
        color="primary"
        rounded="lg"
        class="mb-1"
      />
    </v-list>
  </v-navigation-drawer>

  <v-main>
    <v-container fluid class="pb-6 pr-6 pl-12" style="padding-top: 72px;">
      <router-view />
    </v-container>
  </v-main>

  <v-snackbar
    v-model="notify.visible"
    :color="notify.color"
    :timeout="notify.timeout"
    location="bottom right"
  >
    {{ notify.text }}
    <template #actions>
      <v-btn variant="text" @click="notify.visible = false">Close</v-btn>
    </template>
  </v-snackbar>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useNotificationStore } from '@wallet-tools/shared-frontend/stores/notification'
import TopStatusBar from '../components/TopStatusBar.vue'

const router = useRouter()
const navRoutes = computed(() => router.getRoutes().filter(r => r.meta?.title))
const notify = useNotificationStore()
</script>

<style scoped>
:deep(.v-navigation-drawer.drep-drawer) {
  top: 72px !important;
  bottom: 24px !important;
  height: auto !important;
  margin-left: 24px !important;
  border-radius: 8px !important;
  overflow: hidden;
}
</style>
