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

  <v-snackbar v-model="notify.visible" :color="notify.color" :timeout="notify.timeout" location="bottom right">
    {{ notify.text }}
    <template #actions>
      <v-btn variant="text" @click="notify.visible = false">Close</v-btn>
    </template>
  </v-snackbar>

  <v-dialog v-model="showWarning" persistent max-width="640">
    <v-card>
      <v-card-title>Air-gap reminder</v-card-title>
      <v-card-text>
        <p class="text-body-1 mb-4" style="color: #FFFFFF;">
          The DRep Tools signer must run on a machine isolated from the network.
          Before proceeding, confirm that all network adapters are disabled,
          that this machine is dedicated to signing only, that it is free from
          viruses and malware, and that you will visually verify each
          transaction before approving the signature.
        </p>
        <p class="text-body-1 mb-4" style="color: #FFFFFF;">
          The air-gap indicator in the top bar reflects only IP-traffic on
          local interfaces. File transfer via VM shared folders, USB-passthrough,
          Bluetooth file-transfer (OBEX), or out-of-band management interfaces
          is not detected — those remain your responsibility.
        </p>
        <p class="text-body-1" style="color: #FFFFFF;">
          This machine holds your DRep signing key. Compromise of this machine
          compromises your governance identity. Treat it accordingly.
        </p>
      </v-card-text>
      <v-card-actions class="pa-4">
        <v-spacer />
        <v-btn color="primary" variant="tonal" @click="acknowledgeWarning">I understand — proceed</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import TopStatusBar from '../components/TopStatusBar.vue'

const router = useRouter()
const navRoutes = computed(() => router.getRoutes().filter(r => r.meta?.title))
const notify = useNotificationStore()

const ACK_KEY = 'drep-tools-signer-acknowledged'
const showWarning = ref(sessionStorage.getItem(ACK_KEY) !== 'true')

function acknowledgeWarning() {
  sessionStorage.setItem(ACK_KEY, 'true')
  showWarning.value = false
}
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
