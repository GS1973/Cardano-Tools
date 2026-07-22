import { createRouter, createWebHistory } from 'vue-router'
import PairingView from '@drep-tools/shared-frontend/views/PairingView.vue'
import VoteView from '../views/VoteView.vue'
import RationaleView from '../views/RationaleView.vue'
import RegisterView from '../views/RegisterView.vue'
import UpdateView from '../views/UpdateView.vue'
import RetireView from '../views/RetireView.vue'
import SetupView from '../views/SetupView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: VoteView, meta: { title: 'Vote', icon: 'mdi-gavel' } },
    { path: '/rationale', component: RationaleView, meta: { title: 'Rationale', icon: 'mdi-file-sign' } },
    { path: '/register', component: RegisterView, meta: { title: 'Register', icon: 'mdi-account-plus' } },
    { path: '/update', component: UpdateView, meta: { title: 'Update / refresh', icon: 'mdi-refresh' } },
    { path: '/retire', component: RetireView, meta: { title: 'Retire', icon: 'mdi-account-remove' } },
    { path: '/pairing', component: PairingView, meta: { title: 'Pairing', icon: 'mdi-shield-key-outline' } },
    { path: '/setup', component: SetupView, meta: { title: 'Setup', icon: 'mdi-cog' } },
  ],
})

export default router
