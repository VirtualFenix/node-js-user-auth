/**
 * @fileoverview Punto de entrada principal para la aplicación de autenticación de usuarios en Node.js.
 * Configura un servidor Express y define una ruta básica.
 */
import express from 'express'
import cookieParser from 'cookie-parser'
import { SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import JWT from 'jsonwebtoken'

const PORT = process.env.PORT ?? 3000
const app = express()

app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }
  try {
    const data = JWT.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch (error) {}
  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = JWT.sign({ id: user._id, username: user.username }, SECRET_JWT_KEY, {
      expiresIn: '1h'
    })
    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000
      })
      .json(user)
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
})
app.post('/register', async (req, res) => {
  const { username, password } = req.body
  console.log(req.body)
  try {
    const id = await UserRepository.create({ username, password })
    res.json({ id })
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})
app.post('/logout', (req, res) => {
  res.clearCookie('access_token').json({ message: 'logged out' })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).json({ error: 'unauthorized' })
  res.render('protected', user)
})
/**
 * Inicia el servidor Express en el puerto especificado.
 * Muestra un mensaje en la consola una vez que el servidor está en funcionamiento.
 */
app.listen(PORT, () => {
  console.log(`El servidor está funcionando en http://localhost:${PORT}`)
})
