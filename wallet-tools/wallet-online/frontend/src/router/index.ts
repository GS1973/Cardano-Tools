import { createRouter, createWebHistory } from 'vue-router'
import PairingView from '@wallet-tools/shared-frontend/views/PairingView.vue'
import PaymentView from '../views/PaymentView.vue'
import PoolDelegateView from '../views/PoolDelegateView.vue'
import DrepDelegateView from '../views/DrepDelegateView.vue'
import WithdrawView from '../views/WithdrawView.vue'
import NewAddressView from '../views/NewAddressView.vue'
import AddressBookView from '../views/AddressBookView.vue'
import SetupView from '../views/SetupView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: PaymentView, meta: { title: 'Send payment', icon: 'mdi-send' } },
    { path: '/pool-delegate', component: PoolDelegateView, meta: { title: 'Delegate stake', icon: 'mdi-account-arrow-right' } },
    { path: '/drep-delegate', component: DrepDelegateView, meta: { title: 'Delegate vote', icon: 'mdi-vote' } },
    { path: '/withdraw', component: WithdrawView, meta: { title: 'Withdraw rewards', icon: 'mdi-cash-plus' } },
    { path: '/new-address', component: NewAddressView, meta: { title: 'New address', icon: 'mdi-key-plus' } },
    { path: '/address-book', component: AddressBookView, meta: { title: 'Address book', icon: 'mdi-book-account' } },
    { path: '/pairing', component: PairingView, meta: { title: 'Pairing', icon: 'mdi-shield-key-outline' } },
    { path: '/setup', component: SetupView, meta: { title: 'Setup', icon: 'mdi-cog' } },
  ],
})

export default router
