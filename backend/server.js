import Fastify from 'fastify'
import path from 'path'
import fastifyStatic from '@fastify/static'
import multipart from '@fastify/multipart'
import cookie from '@fastify/cookie'
import jwt from '@fastify/jwt'
import formbody from '@fastify/formbody'
import cors from '@fastify/cors'
import bcrypt from 'bcrypt'
import { openDB } from './database.js'
import helmet from '@fastify/helmet'
import rateLimit from '@fastify/rate-limit'

// Docker пути
const UPLOADS_DIR = '/app/uploads'
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_to_a_strong_secret'

const fastify = Fastify({
	logger: true,
	trustProxy: true
})

// Раздаём ТОЛЬКО uploads (картинки профилей)
fastify.register(fastifyStatic, {
	root: UPLOADS_DIR,
	prefix: '/uploads/',
})

fastify.register(helmet, {
	contentSecurityPolicy: {
		directives: {
			defaultSrc: ["'self'"],
			styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
			fontSrc: ["'self'", "https://fonts.gstatic.com"],
			imgSrc: ["'self'", "data:", "blob:"],
			scriptSrc: ["'self'", "'unsafe-inline'"],
			connectSrc: ["'self'"]
		}
	},
	crossOriginEmbedderPolicy: false
})

fastify.register(formbody)
fastify.register(cors, { origin: true, credentials: true })
fastify.register(cookie, { secret: JWT_SECRET })
fastify.register(jwt, { secret: JWT_SECRET })
fastify.register(multipart)

fastify.register(rateLimit, {
	max: 100,
	timeWindow: '15 minutes',
	skipOnError: true,
	allowList: (req) => {
		return req.url.startsWith('/uploads')
	}
})

fastify.decorate("authenticate", async (request, reply) => {
	try {
		const token = request.cookies?.token
		if (!token) return reply.code(401).send({ message: 'Not authenticated' })
		const decoded = fastify.jwt.verify(token)
		request.user = decoded
	}
	catch (err) {
		return reply.code(401).send({ message: 'Authentication error' })
	}
})

fastify.post('/registration', async (request, reply) => {
	const { login, email, password } = request.body
	if (!login || !email || !password)
		return reply.code(400).send({ message: 'All fields are mandatory!' })
	if (!/^[a-zA-Z0-9_]+$/.test(login))
		return reply.code(400).send({ message: 'Invalid login format!' })
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
		return reply.code(400).send({ message: 'Invalid email format!' })
	if (password.length < 6)
		return reply.code(400).send({ message: 'Password must be at least 6 characters!' })
	try {
		const db = await openDB()
		const existingLogin = await db.get(`SELECT id FROM users WHERE login = ?`, [login])
		if (existingLogin)
			return reply.code(400).send({ message: 'This login is already taken!' })
		const existingEmail = await db.get(`SELECT id FROM users WHERE email = ?`, [email])
		if (existingEmail)
			return reply.code(400).send({ message: 'This email is already taken!' })
		const hashedPassword = await bcrypt.hash(password, 10)
		await db.run('INSERT INTO users (login, email, password) VALUES (?, ?, ?)', [login, email, hashedPassword])
		return reply.code(200).send({ message: 'Registration successful!' })
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Registration error: ' + err.message })
	}
})

fastify.post('/login', async (request, reply) => {
	const { login, password } = request.body
	if (!login || !password)
		return reply.code(400).send({ message: 'Login and password required' })
	try {
		const db = await openDB()
		const user = await db.get('SELECT * FROM users WHERE login = ?', [login])
		if (!user)
			return reply.code(401).send({ message: 'User not found' })
		const match = await bcrypt.compare(password, user.password)
		if (!match)
			return reply.code(401).send({ message: 'Incorrect password' })
		const token = fastify.jwt.sign(
			{ id: user.id, login: user.login },
			{ expiresIn: '6h' }
		)
		reply.setCookie('token', token, {
			httpOnly: true,
			sameSite: 'lax',
			path: '/',
			maxAge: 60 * 60 * 6,
			secure: process.env.NODE_ENV === 'production'
		})
		return reply.code(200).send({ message: 'Login successful' })
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Login error: ' + err.message })
	}
})

fastify.post('/logout', async (request, reply) => {
	reply.clearCookie('token', { path: '/' }).code(200).send({ message: 'Logged out' })
})

fastify.get('/profile', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	try {
		const { id } = request.user
		const db = await openDB()
		const u = await db.get('SELECT id, login, email, avatar FROM users WHERE id = ?', [id])
		if (!u) return reply.code(404).send({ message: 'User not found' })
		return reply.send(u)
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Error fetching profile' })
	}
})

fastify.put('/profile', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	const { login, email, password } = request.body || {}
	const { id } = request.user
	if (!login || !email) return reply.code(400).send({ message: 'Login and email required' })
	if (!/^[a-zA-Z0-9_]+$/.test(login)) return reply.code(400).send({ message: 'Invalid login characters' })
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply.code(400).send({ message: 'Invalid email' })
	if (password && password.length < 6) return reply.code(400).send({ message: 'Password too short' })
	try {
		const db = await openDB()
		const existingLogin = await db.get('SELECT id FROM users WHERE login = ? AND id != ?', [login, id])
		if (existingLogin) return reply.code(400).send({ message: 'Login is already taken' })
		const existingEmail = await db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, id])
		if (existingEmail) return reply.code(400).send({ message: 'Email is already taken' })
		let sql, params
		if (password && password !== '') {
			const hashed = await bcrypt.hash(password, 10)
			sql = 'UPDATE users SET login = ?, email = ?, password = ? WHERE id = ?'
			params = [login, email, hashed, id]
		}
		else {
			sql = 'UPDATE users SET login = ?, email = ? WHERE id = ?'
			params = [login, email, id]
		}
		await db.run(sql, params)
		return reply.code(200).send({ message: 'Profile updated' })
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Update error' })
	}
})

fastify.delete('/profile', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	try {
		const { id } = request.user
		const db = await openDB()
		const row = await db.get('SELECT avatar FROM users WHERE id = ?', [id])
		const oldAvatar = row?.avatar || ''
		if (oldAvatar && oldAvatar !== 'default.png') {
			const fp = path.join(UPLOADS_DIR, oldAvatar)
			try {
				await import('fs/promises').then(fs => fs.unlink(fp))
			} catch (e) { /* ignore */ }
		}
		await db.run('DELETE FROM users WHERE id = ?', [id])
		reply.clearCookie('token', { path: '/' })
		return reply.code(200).send({ message: 'Profile deleted' })
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Delete error' })
	}
})

import { pipeline } from 'stream'
import { promisify } from 'util'
const pump = promisify(pipeline)
import fs from 'fs'
import { promisify as p } from 'util'
const fsUnlink = p(fs.unlink)
const fsAccess = p(fs.access)
const fsMkdir = p(fs.mkdir)

async function ensureUploadsDir() {
	try {
		await fsAccess(UPLOADS_DIR)
	}
	catch {
		await fsMkdir(UPLOADS_DIR, { recursive: true })
	}
}

fastify.post('/avatar', async (request, reply) => {
	try {
		const token = request.cookies?.token
		if (!token) {
			return reply.code(401).send({ message: 'Not authenticated' })
		}
		const decoded = fastify.jwt.verify(token)
		request.user = decoded
	}
	catch (err) {
		request.log.error(err)
		return reply.code(401).send({ message: 'Authentication error' })
	}
	await ensureUploadsDir()
	const { id } = request.user
	const data = await request.file()
	if (!data) {
		return reply.code(400).send({ message: 'No file uploaded' })
	}
	if (!data.filename) {
		return reply.code(400).send({ message: 'No file' })
	}
	const allowed = ['image/jpeg', 'image/png', 'image/webp']
	if (!allowed.includes(data.mimetype)) {
		return reply.code(400).send({ message: 'Invalid image format' })
	}
	const ext = path.extname(data.filename).toLowerCase()
	const newName = Date.now() + '-' + Math.random().toString(36).slice(2, 9) + ext
	const destPath = path.join(UPLOADS_DIR, newName)
	try {
		await pump(data.file, fs.createWriteStream(destPath))
		const db = await openDB()
		const row = await db.get('SELECT avatar FROM users WHERE id = ?', [id])
		const oldAvatar = row?.avatar || ''
		if (oldAvatar && oldAvatar !== 'default.png') {
			try {
				await fsUnlink(path.join(UPLOADS_DIR, oldAvatar))
			}
			catch(e) { /* ignore */ }
		}
		await db.run('UPDATE users SET avatar = ? WHERE id = ?', [newName, id])
		return reply.code(200).send({ message: 'Avatar uploaded', avatar: newName })
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Upload error' })
	}
})

fastify.delete('/avatar', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	try {
		const { id } = request.user
		const db = await openDB()
		const row = await db.get('SELECT avatar FROM users WHERE id = ?', [id])
		const oldAvatar = row?.avatar || ''
		if (oldAvatar && oldAvatar !== 'default.png') {
			try { await fsUnlink(path.join(UPLOADS_DIR, oldAvatar)) } catch (e) { /* ignore */ }
		}
		await db.run('UPDATE users SET avatar = ? WHERE id = ?', ['', id])
		return reply.code(200).send({ message: 'Avatar deleted' })
	}
	catch (err) {
		request.log.error(err)
		return reply.code(500).send({ message: 'Delete avatar error' })
	}
})

const start = async () => {
	try {
		await fastify.listen({ 
			port: 3000,
			host: '0.0.0.0'
		})
	}
	catch (err) {
		fastify.log.error(err)
		process.exit(1)
	}
}

start()
