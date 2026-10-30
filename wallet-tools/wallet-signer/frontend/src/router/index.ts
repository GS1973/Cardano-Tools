import { createRouter, createWebHistory } from 'vue-router'
import PairingView from '@wallet-tools/shared-frontend/views/PairingView.vue'
import SignView from '../views/SignView.vue'
import SetupView from '../views/SetupView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: SignView, meta: { title: 'Sign', icon: 'mdi-key-variant' } },
    { path: '/pairing', component: PairingView, meta: { title: 'Pairing', icon: 'mdi-shield-key-outline' } },
    { path: '/setup', component: SetupView, meta: { title: 'Setup', icon: 'mdi-cog' } },
  ],
})

export default router
