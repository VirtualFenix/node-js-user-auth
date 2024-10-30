import crypto from 'node:crypto'
import bcrypt from 'bcrypt'
import DBLocal from 'db-local'
import { SALT_ROUNDS } from './config.js'

const { Schema } = DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})
export class UserRepository {
  static async create ({ username, password }) {
    Validation.username({ username })
    Validation.password({ password })
    // 3. check if username already exists
    const user = User.findOne({ username })
    if (user) throw new Error('username already exists')
    // 4. create id
    const id = crypto.randomUUID()
    // 5. hash password y guardarlo en una constante hashedpassword
    const hashedPassword = await bcrypt.hashSync(password, SALT_ROUNDS)

    // 5. create user
    User.create({ _id: id, username, password: hashedPassword }).save()
    // 6. return id
    return id
  }

  static async login ({ username, password }) {
    Validation.username({ username })
    Validation.passwordLogin({ password })
    // 7. check if username exists
    const user = User.findOne({ username })
    if (!user) throw new Error('username does not exist')
    // 8. compare passwords
    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('password is incorrect')
    const { password: _, ...publicUser } = user
    return publicUser
  }
}

// crear una clase para las validar los datos de los usuarios y usan el metodo static

class Validation {
  // 1. validation username
  static username ({ username }) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters')
  }

  // 2. validation password
  static password ({ password }) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('password must be at least 6 characters')
  }

  static passwordLogin ({ password }) {
    if (typeof password !== 'string') throw new Error('password must be a string')
  }
}
