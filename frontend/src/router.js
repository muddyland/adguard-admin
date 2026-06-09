import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from './stores/auth'

import Login from './views/Login.vue'
import Dashboard from './views/Dashboard.vue'
import Zones from './views/Zones.vue'
import Servers from './views/Servers.vue'
import Records from './views/Records.vue'
import Provision from './views/Provision.vue'
import Users from './views/Users.vue'

const routes = [
  { path: '/login', name: 'login', component: Login, meta: { public: true } },
  { path: '/', name: 'dashboard', component: Dashboard },
  { path: '/zones', name: 'zones', component: Zones },
  { path: '/servers', name: 'servers', component: Servers },
  { path: '/records', name: 'records', component: Records },
  { path: '/provision', name: 'provision', component: Provision, meta: { editor: true } },
  { path: '/users', name: 'users', component: Users, meta: { admin: true } },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async (to) => {
  const auth = useAuth()
  if (to.meta.public) return true
  if (!auth.token) return { name: 'login' }
  if (!auth.user) {
    try { await auth.fetchMe() } catch { return { name: 'login' } }
  }
  if (to.meta.admin && !auth.isAdmin) return { name: 'dashboard' }
  if (to.meta.editor && !auth.isEditor) return { name: 'dashboard' }
  return true
})

export default router
