import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

// Attach the JWT to every request.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Bounce to login on 401.
api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response?.status === 401 && !location.pathname.startsWith('/login')) {
      localStorage.removeItem('token')
      location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default api
