import { createRouter, createWebHistory } from 'vue-router'
import PairingView from '@spo-tools/shared-frontend/views/PairingView.vue'
import PoolView from '../views/PoolView.vue'
import LeaderlogView from '../views/LeaderlogView.vue'
import KESRotationView from '../views/KESRotationView.vue'
import SetupView from '../views/SetupView.vue'
import WithdrawView from '../views/WithdrawView.vue'
import DRepDelegationView from '../views/DRepDelegationView.vue'
import GovernanceVoteView from '../views/GovernanceVoteView.vue'
import RationaleView from '../views/RationaleView.vue'
import PoolParamsView from '../views/PoolParamsView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: PoolView,
      meta: { title: 'Pool', icon: 'mdi-server-network' },
    },
    {
      path: '/leaderlog',
      component: LeaderlogView,
      meta: { title: 'Leaderlog', icon: 'mdi-calendar-clock' },
    },
    {
      path: '/kes-rotation',
      component: KESRotationView,
      meta: { title: 'KES Rotation', icon: 'mdi-key-chain-variant' },
    },
    {
      path: '/withdraw',
      component: WithdrawView,
      meta: { title: 'Withdraw', icon: 'mdi-cash-multiple' },
    },
    {
      path: '/drep',
      component: DRepDelegationView,
      meta: { title: 'DRep delegation', icon: 'mdi-vote-outline' },
    },
    {
      path: '/vote',
      component: GovernanceVoteView,
      meta: { title: 'SPO vote', icon: 'mdi-gavel' },
    },
    {
      path: '/rationale',
      component: RationaleView,
      meta: { title: 'Rationale', icon: 'mdi-file-sign' },
    },
    {
      path: '/pool-params',
      component: PoolParamsView,
      meta: { title: 'Pool parameters', icon: 'mdi-tune' },
    },
    {
      path: '/pairing',
      component: PairingView,
      meta: { title: 'Pairing', icon: 'mdi-shield-key-outline' },
    },
    {
      path: '/setup',
      component: SetupView,
      meta: { title: 'Setup', icon: 'mdi-cog' },
    },
  ],
})

export default router
