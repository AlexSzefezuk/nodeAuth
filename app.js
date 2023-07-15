const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const User = require('./models/User')

require('dotenv').config()

const app = express()
app.use(express.json())

const checkToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    res.status(401).json({ msg: 'Acesso negado' })
  }

  try {
    const secret = process.env.SECRET
    jwt.verify(token, secret)

    next()
  } catch (error) {
    res.status(400).json({ msg: 'Token Inválido' })
  }
}

app.get('/user/:id', checkToken, async (req, res) => {
  const id = req.params.id

  const user = await User.findById(id, '-password')

  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado' })
  }

  return res.status(200).json({ msg: 'Usuário encontrado', user })
})

app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmedPassword } = req.body

  if (!name) {
    return res.status(422).json({ msg: 'Nome é obrigatório' })
  }
  if (!email) {
    return res.status(422).json({ msg: 'Email é obrigatório' })
  }
  if (!password) {
    return res.status(422).json({ msg: 'Senha é obrigatória' })
  }
  if (password !== confirmedPassword) {
    return res.status(422).json({ msg: 'As senhas não conferem' })
  }

  const userExists = await User.findOne({ email })

  if (userExists) {
    return res.status(422).json({ msg: 'Email já cadastrado' })
  }

  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try {
    await user.save()
    res.status(201).json({ msg: 'Usuário criado com sucesso' })
  } catch (error) {
    console.log(error)
    res.status(500).json({ msg: 'Ocorreu algum erro' })
  }
})

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email) {
    return res.status(422).json({ msg: 'Email é obrigatório' })
  }
  if (!password) {
    return res.status(422).json({ msg: 'Senha é obrigatória' })
  }

  const user = await User.findOne({ email })

  if (!user) {
    return res.status(422).json({ msg: 'Credenciais inválidas' })
  }

  const matchPassword = await bcrypt.compare(password, user.password)

  if (!matchPassword) {
    return res.status(422).json({ msg: 'Credenciais inválidas' })
  }

  try {
    const secret = process.env.SECRET

    const token = jwt.sign(
      {
        id: user._id
      },
      secret
    )

    res.status(200).json({ msg: 'Autenticação feita com sucesso', token })
  } catch (error) {
    console.log(error)
    res.status(500).json({ msg: 'Ocorreu algum erro' })
  }
})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.dcghnkg.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(process.env.PORT || 3000)
    console.log('DB Conected')
  })
  .catch(err => console.log(err))
