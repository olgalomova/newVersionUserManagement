import Fastify from 'fastify'
import path from 'path'
import fastifyStatic from '@fastify/static'
import multipart from '@fastify/multipart'
import cookie from '@fastify/cookie'
import jwt from '@fastify/jwt'
import formbody from '@fastify/formbody'
import cors from '@fastify/cors'
import { openDB } from './database.js'
import helmet from '@fastify/helmet'
import rateLimit from '@fastify/rate-limit'
import fetch from "node-fetch"
import { pipeline } from 'stream'
import { promisify } from 'util'
import fs from 'fs'
import bcrypt from 'bcryptjs'

const pump = promisify(pipeline)
const fsUnlink = promisify(fs.unlink)
const fsAccess = promisify(fs.access)
const fsMkdir = promisify(fs.mkdir)

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || "https://olomova.42.fr/auth/google/callback"
const UPLOADS_DIR = '/app/uploads'
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_to_a_strong_secret'

const fastify = Fastify({
	logger: true,
	trustProxy: true
})

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
			connectSrc: ["'self'", "https://accounts.google.com", "https://oauth2.googleapis.com", "https://www.googleapis.com"]
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

async function ensureUploadsDir() {
	try {
		await fsAccess(UPLOADS_DIR)
	}
	catch {
		await fsMkdir(UPLOADS_DIR, { recursive: true })
	}
}

fastify.post('/registration', async (request, reply) => {
	let db
	try {
		const { login, email, password } = request.body
		const onlineStatus = 'offline'
		if (!login || !email || !password)
			return reply.code(400).send({ message: 'All fields are mandatory!' })
		if (!/^[a-zA-Z0-9_]+$/.test(login))
			return reply.code(400).send({ message: 'Invalid login format!' })
		if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
			return reply.code(400).send({ message: 'Invalid email format!' })
		if (password.length < 6)
			return reply.code(400).send({ message: 'Password must be at least 6 characters!' })

		db = await openDB()
		const existingLogin = await db.get(`SELECT id FROM users WHERE login = ?`, [login])
		if (existingLogin) {
			await db.close()
			return reply.code(400).send({ message: 'This login is already taken!' })
		}
		const existingEmail = await db.get(`SELECT id FROM users WHERE email = ?`, [email])
		if (existingEmail) {
			await db.close()
			return reply.code(400).send({ message: 'This email is already taken!' })
		}
		request.log.info('Starting password hashing...')
		const hashedPassword = await bcrypt.hashSync(password, 10)
		request.log.info('Hashing successful.')
		await db.run('INSERT INTO users (login, email, password, onlineStatus) VALUES (?, ?, ?, ?)', [login, email, hashedPassword, onlineStatus])
		await db.close()
		return reply.code(200).send({ message: 'Registration successful!' })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Registration error: ' + err.message })
	}
})

fastify.post('/login', async (request, reply) => {
	let db
	try {
		const { login, password } = request.body
		if (!login || !password)
			return reply.code(400).send({ message: 'Login and password required' })

		db = await openDB()
		const user = await db.get('SELECT * FROM users WHERE login = ?', [login])
		if (!user) {
			await db.close()
			return reply.code(401).send({ message: 'User not found' })
		}
		const match = await bcrypt.compare(password, user.password)
		if (!match) {
			await db.close()
			return reply.code(401).send({ message: 'Incorrect password' })
		}
		const token = fastify.jwt.sign(
			{ id: user.id, login: user.login },
			{ expiresIn: '6h' }
		)
		reply.setCookie('token', token, {
			httpOnly: true,
			sameSite: 'strict',
			path: '/',
			maxAge: 60 * 60 * 6,
			secure: true
		})
		await db.run('UPDATE users SET onlineStatus = ? WHERE id = ?', ['online', user.id])
		await db.close()
		return reply.code(200).send({ message: 'Login successful' })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Login error: ' + err.message })
	}
})

fastify.post('/logout', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { id } = request.user
		db = await openDB()
		await db.run('UPDATE users SET onlineStatus = ? WHERE id = ?', ['offline', id])
		await db.close()
		reply.clearCookie('token', { path: '/' }).code(200).send({ message: 'Logged out' })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Logout error' })
	}
})

fastify.get('/profile', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { id } = request.user
		db = await openDB()
		const u = await db.get('SELECT id, login, email, avatar, onlineStatus, wins, losses, draws, total_games FROM users WHERE id = ?', [id])
		await db.close()
		if (!u) return reply.code(404).send({ message: 'User not found' })
		return reply.send(u)
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Error fetching profile' })
	}
})

fastify.put('/profile', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { login, email, password } = request.body || {}
		const { id } = request.user
		if (!login || !email) return reply.code(400).send({ message: 'Login and email required' })
		if (!/^[a-zA-Z0-9_]+$/.test(login)) return reply.code(400).send({ message: 'Invalid login characters' })
		if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply.code(400).send({ message: 'Invalid email' })
		if (password && password.length < 6) return reply.code(400).send({ message: 'Password too short' })

		db = await openDB()
		const existingLogin = await db.get('SELECT id FROM users WHERE login = ? AND id != ?', [login, id])
		if (existingLogin) {
			await db.close()
			return reply.code(400).send({ message: 'Login is already taken' })
		}
		const existingEmail = await db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, id])
		if (existingEmail) {
			await db.close()
			return reply.code(400).send({ message: 'Email is already taken' })
		}
		let sql, params
		if (password && password !== '') {
			const hashed = bcrypt.hashSync(password, 10)
			sql = 'UPDATE users SET login = ?, email = ?, password = ? WHERE id = ?'
			params = [login, email, hashed, id]
		}
		else {
			sql = 'UPDATE users SET login = ?, email = ? WHERE id = ?'
			params = [login, email, id]
		}
		await db.run(sql, params)
		await db.close()
		return reply.code(200).send({ message: 'Profile updated' })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Update error' })
	}
})

fastify.delete('/profile', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { id } = request.user
		db = await openDB()
		const row = await db.get('SELECT avatar FROM users WHERE id = ?', [id])
		const oldAvatar = row?.avatar || ''
		if (oldAvatar && oldAvatar !== 'default.png') {
			const fp = path.join(UPLOADS_DIR, oldAvatar)
			try {
				await import('fs/promises').then(fs => fs.unlink(fp))
			} catch (e) { /* ignore */ }
		}
		await db.run('DELETE FROM users WHERE id = ?', [id])
		await db.close()
		reply.clearCookie('token', { path: '/' })
		return reply.code(200).send({ message: 'Profile deleted' })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Delete error' })
	}
})

fastify.get('/search', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { query } = request.query

		if (!query || query.trim() === "") {
			return reply.code(400).send({ message: "Query is required", users: [] })
		}

		db = await openDB()
		const users = await db.all(
			`SELECT id, login, email, avatar, onlineStatus FROM users WHERE login LIKE ? LIMIT 30`,
			[`%${query}%`]
		)
		await db.close()
		return reply.send({ users })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Search error" })
	}
})

fastify.post('/friend-request', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { addressee_id } = request.body
		const requester_id = request.user.id

		if (!addressee_id) {
			return reply.code(400).send({ message: "Addressee ID is required" })
		}

		if (requester_id === addressee_id) {
			return reply.code(400).send({ message: "You cannot add yourself" })
		}

		db = await openDB()

		const addressee = await db.get('SELECT id FROM users WHERE id = ?', [addressee_id])
		if (!addressee) {
			await db.close()
			return reply.code(404).send({ message: "User not found" })
		}

		const existingRequest = await db.get(
			`SELECT id, status FROM friends
			 WHERE (requester_id = ? AND addressee_id = ?)
			 OR (requester_id = ? AND addressee_id = ?)`,
			[requester_id, addressee_id, addressee_id, requester_id]
		)

		if (existingRequest) {
			await db.close()
			if (existingRequest.status === 'pending') {
				return reply.code(400).send({ message: "Friend request already sent" })
			} else if (existingRequest.status === 'accepted') {
				return reply.code(400).send({ message: "You are already friends" })
			}
		}

		await db.run(
			`INSERT INTO friends (requester_id, addressee_id, status) VALUES (?, ?, 'pending')`,
			[requester_id, addressee_id]
		)

		await db.close()
		return reply.code(200).send({ message: "Friend request sent" })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error sending friend request" })
	}
})

fastify.delete('/friend-remove', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const userId = request.user.id
		const { friend_id } = request.body

		if (!friend_id) {
			return reply.code(400).send({ message: "Friend ID is required" })
		}

		db = await openDB()

		const result = await db.run(
			`DELETE FROM friends
			 WHERE (requester_id = ? AND addressee_id = ?)
			 OR (requester_id = ? AND addressee_id = ?)`,
			[userId, friend_id, friend_id, userId]
		)

		await db.close()

		if (result.changes === 0) {
			return reply.code(404).send({ message: "Friend record not found" })
		}

		return reply.code(200).send({ message: "Friend removed" })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error removing friend" })
	}
})

fastify.get('/friends', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const userId = request.user.id
		db = await openDB()

		const friends = await db.all(
			`SELECT u.id, u.login, u.email, u.avatar, u.onlineStatus
			 FROM users u
			 WHERE (
				(SELECT status FROM friends WHERE requester_id = ? AND addressee_id = u.id) = 'accepted'
				OR
				(SELECT status FROM friends WHERE requester_id = u.id AND addressee_id = ?) = 'accepted'
			 )`,
			[userId, userId]
		)

		await db.close()
		return reply.code(200).send({ friends: friends || [] })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error loading friends" })
	}
})

fastify.post('/friend-accept', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { request_id } = request.body
		const user_id = request.user.id

		if (!request_id) {
			return reply.code(400).send({ message: "Request ID is required" })
		}

		db = await openDB()

		const friendRequest = await db.get(
			'SELECT id, requester_id FROM friends WHERE id = ? AND addressee_id = ? AND status = "pending"',
			[request_id, user_id]
		)

		if (!friendRequest) {
			await db.close()
			return reply.code(404).send({ message: "Friend request not found" })
		}

		await db.run(
			'UPDATE friends SET status = "accepted" WHERE id = ?',
			[request_id]
		)

		const friend = await db.get(
			'SELECT id, login, email, avatar, onlineStatus FROM users WHERE id = ?',
			[friendRequest.requester_id]
		)

		await db.close()
		return reply.code(200).send({ message: "Friend request accepted", friend })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error accepting friend request" })
	}
})

fastify.post('/friend-reject', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { request_id } = request.body
		const user_id = request.user.id

		if (!request_id) {
			return reply.code(400).send({ message: "Request ID is required" })
		}

		db = await openDB()

		const friendRequest = await db.get(
			'SELECT id FROM friends WHERE id = ? AND addressee_id = ? AND status = "pending"',
			[request_id, user_id]
		)

		if (!friendRequest) {
			await db.close()
			return reply.code(404).send({ message: "Friend request not found" })
		}

		await db.run('DELETE FROM friends WHERE id = ?', [request_id])

		await db.close()
		return reply.code(200).send({ message: "Friend request rejected" })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error rejecting friend request" })
	}
})

fastify.get('/friend-requests', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const user_id = request.user.id
		db = await openDB()

		const requests = await db.all(
			`SELECT
				f.id,
				f.requester_id,
				u.id as user_id,
				u.login,
				u.email,
				u.avatar,
				u.onlineStatus
			FROM friends f
			JOIN users u ON f.requester_id = u.id
			WHERE f.addressee_id = ? AND f.status = 'pending'
			ORDER BY f.created_at DESC`,
			[user_id]
		)

		await db.close()
		return reply.send({ requests: requests || [] })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error fetching friend requests" })
	}
})

fastify.post('/avatar', async (request, reply) => {
	let db
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
		db = await openDB()
		const row = await db.get('SELECT avatar FROM users WHERE id = ?', [id])
		const oldAvatar = row?.avatar || ''
		if (oldAvatar && oldAvatar !== 'default.png') {
			try {
				await fsUnlink(path.join(UPLOADS_DIR, oldAvatar))
			}
			catch(e) { /* ignore */ }
		}
		await db.run('UPDATE users SET avatar = ? WHERE id = ?', [newName, id])
		await db.close()
		return reply.code(200).send({ message: 'Avatar uploaded', avatar: newName })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Upload error' })
	}
})

fastify.delete('/avatar', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { id } = request.user
		db = await openDB()
		const row = await db.get('SELECT avatar FROM users WHERE id = ?', [id])
		const oldAvatar = row?.avatar || ''
		if (oldAvatar && oldAvatar !== 'default.png') {
			try { await fsUnlink(path.join(UPLOADS_DIR, oldAvatar)) } catch (e) { /* ignore */ }
		}
		await db.run('UPDATE users SET avatar = ? WHERE id = ?', ['', id])
		await db.close()
		return reply.code(200).send({ message: 'Avatar deleted' })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: 'Delete avatar error' })
	}
})

fastify.get('/auth/google', async (req, reply) => {
	const url =
		"https://accounts.google.com/o/oauth2/v2/auth?" +
		new URLSearchParams({
			client_id: GOOGLE_CLIENT_ID,
			redirect_uri: GOOGLE_REDIRECT_URI,
			response_type: "code",
			scope: "email profile",
			access_type: "offline",
			prompt: "consent"
		})

	reply.redirect(url)
})

fastify.get('/auth/google/callback', async (req, reply) => {
	let db
	try {
		req.log.error('[CALLBACK START]')
		const code = req.query.code
		req.log.info('=== Google Callback Started ===')

		if (!code) {
			req.log.error('No code from Google')
			return reply.code(400).send({ message: "No code from Google" })
		}

		req.log.info('Getting token from Google...')
		const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				client_id: GOOGLE_CLIENT_ID,
				client_secret: GOOGLE_CLIENT_SECRET,
				code,
				redirect_uri: GOOGLE_REDIRECT_URI,
				grant_type: "authorization_code",
			}),
		})

		const tokenData = await tokenResponse.json()
		req.log.info('Token response:', JSON.stringify(tokenData))

		if (!tokenData.access_token) {
			req.log.error('Token error:', JSON.stringify(tokenData))
			return reply.code(400).send({ message: "Failed to get Google token" })
		}

		req.log.info('Getting user profile...')
		const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
			headers: { Authorization: `Bearer ${tokenData.access_token}` },
		})

		const googleUser = await profileRes.json()
		req.log.info('User profile received:', googleUser.email)

		const email = googleUser.email
		const login = googleUser.name.replace(/\s+/g, "_")

		req.log.info('[DB] About to open database...')
		db = await openDB()
		req.log.info('[DB] Database opened successfully')

		req.log.info('[DB] Checking for existing user...')
		let user = await db.get("SELECT * FROM users WHERE email = ?", [email])
		req.log.info('[DB] User query completed:', user ? 'Found' : 'Not found')

		if (!user) {
			req.log.info('[DB] Creating new user with login:', login)
			await db.run(
				`INSERT INTO users (login, email, password, onlineStatus)
				 VALUES (?, ?, ?, 'online')`,
				[login, email, null]
			)
			req.log.info('[DB] Insert completed, fetching user...')

			user = await db.get("SELECT * FROM users WHERE email = ?", [email])
			req.log.info('[DB] User created with ID:', user?.id)
		} else {
			req.log.info('[DB] User already exists with ID:', user.id)
		}

		req.log.info('[DB] Updating user online status...')
		await db.run('UPDATE users SET onlineStatus = ? WHERE id = ?', ['online', user.id])
		req.log.info('[DB] User status updated')

		req.log.info('Creating JWT token...')
		const token = fastify.jwt.sign(
			{ id: user.id, login: user.login },
			{ expiresIn: '6h' }
		)

		reply.setCookie('token', token, {
			httpOnly: true,
			sameSite: 'strict',
			path: '/',
			maxAge: 60 * 60 * 6,
			secure: true
		})

		req.log.info('[DB] Closing database...')
		await db.close()
		req.log.info('[DB] Database closed successfully')

		req.log.info('=== Google Callback Success ===')
		return reply.redirect(process.env.FRONTEND_URL || 'https://olomova.42.fr/')

	}
	catch (err) {
		req.log.error('=== CALLBACK ERROR ===')
		req.log.error('Error type:', err.constructor.name)
		req.log.error('Error message:', err.message)
		req.log.error('Stack:', err.stack)

		if (db) {
			try {
				await db.close()
				req.log.info('Database closed in error handler')
			} catch (closeErr) {
				req.log.error('Error closing database in error handler:', closeErr.message)
			}
		}

		return reply.code(500).send({ message: "Google auth error: " + err.message })
	}
})

//GAME SESSION

fastify.post('/game/create', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { opponent_id } = request.body
		const player1_id = request.user.id

		if (!opponent_id) {
			return reply.code(400).send({ message: "Opponent ID is required" })
		}

		db = await openDB()

		const friendship = await db.get(
			`SELECT id FROM friends WHERE 
			 ((requester_id = ? AND addressee_id = ?) OR 
			  (requester_id = ? AND addressee_id = ?))
			 AND status = 'accepted'`,
			[player1_id, opponent_id, opponent_id, player1_id]
		)

		if (!friendship) {
			await db.close()
			return reply.code(403).send({ message: "You can only play with friends" })
		}

		const gameCode = Math.random().toString(36).substring(2, 9).toUpperCase()
		const result = await db.run(
			`INSERT INTO games (player1_id, player2_id, status, game_code, created_at)
			 VALUES (?, ?, 'waiting', ?, datetime('now'))`,
			[player1_id, opponent_id, gameCode]
		)

		const gameId = result.lastID
		await db.close()

		return reply.code(200).send({ 
			message: "Game created", 
			game_id: gameId,
			game_code: gameCode
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error creating game" })
	}
})

fastify.post('/game/accept', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { game_id } = request.body
		const player2_id = request.user.id

		if (!game_id) {
			return reply.code(400).send({ message: "Game ID is required" })
		}

		db = await openDB()

		const game = await db.get(
			'SELECT * FROM games WHERE id = ? AND player2_id = ? AND status = ?',
			[game_id, player2_id, 'waiting']
		)

		if (!game) {
			await db.close()
			return reply.code(404).send({ message: "Game not found or already started" })
		}

		await db.run(
			'UPDATE games SET status = ? WHERE id = ?',
			['active', game_id]
		)

		await db.close()

		return reply.code(200).send({ 
			message: "Game accepted",
			game_id: game_id,
			game_code: game.game_code
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error accepting game" })
	}
})

fastify.get('/game/:gameId', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { gameId } = request.params
		const userId = request.user.id

		if (!gameId) {
			return reply.code(400).send({ message: "Game ID is required" })
		}

		db = await openDB()

		const game = await db.get(
			`SELECT g.id, g.player1_id, g.player2_id, g.status, g.game_code,
				u1.login as player1_login, u1.avatar as player1_avatar,
				u2.login as player2_login, u2.avatar as player2_avatar
			 FROM games g
			 JOIN users u1 ON g.player1_id = u1.id
			 JOIN users u2 ON g.player2_id = u2.id
			 WHERE g.id = ?`,
			[gameId]
		)

		if (!game) {
			await db.close()
			return reply.code(404).send({ message: "Game not found" })
		}

		if (game.player1_id !== userId && game.player2_id !== userId) {
			await db.close()
			return reply.code(403).send({ message: "You don't have access to this game" })
		}

		await db.close()
		return reply.send(game)
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error fetching game" })
	}
})

fastify.get('/game-pending', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const userId = request.user.id

		db = await openDB()

		const game = await db.get(
			`SELECT g.id, g.player1_id, g.player2_id, g.status, g.game_code,
				u1.login as player1_login, u1.avatar as player1_avatar
			 FROM games g
			 JOIN users u1 ON g.player1_id = u1.id
			 WHERE g.player2_id = ? AND g.status = 'waiting'`,
			[userId]
		)

		await db.close()

		if (!game) {
			return reply.code(404).send({ message: "No pending games" })
		}

		return reply.send(game)
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error fetching pending game" })
	}
})

fastify.post('/game/:gameId/accept', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { gameId } = request.params
		const player2_id = request.user.id

		if (!gameId) {
			return reply.code(400).send({ message: "Game ID is required" })
		}

		db = await openDB()

		const game = await db.get(
			'SELECT * FROM games WHERE id = ? AND player2_id = ? AND status = ?',
			[gameId, player2_id, 'waiting']
		)

		if (!game) {
			await db.close()
			return reply.code(404).send({ message: "Game not found or already started" })
		}

		await db.run(
			'UPDATE games SET status = ? WHERE id = ?',
			['active', gameId]
		)

		await db.close()

		return reply.code(200).send({
			message: "Game accepted",
			game_id: gameId,
			game_code: game.game_code
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error accepting game" })
	}
})

fastify.post('/game/:gameId/finish', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { gameId } = request.params
		const userId = request.user.id

		if (!gameId) {
			return reply.code(400).send({ message: "Game ID is required" })
		}

		db = await openDB()

		const game = await db.get(
			'SELECT id, status FROM games WHERE id = ? AND (player1_id = ? OR player2_id = ?)',
			[gameId, userId, userId]
		)

		if (!game) {
			await db.close()
			return reply.code(404).send({ message: "Game not found" })
		}

		// Если игра еще не завершена, завершаем её
		if (game.status !== 'finished') {
			await db.run(
				'UPDATE games SET status = ? WHERE id = ?',
				['finished', gameId]
			)
		}

		await db.close()

		return reply.code(200).send({
			message: "Game finished",
			game_id: gameId
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error finishing game" })
	}
})

//TOURNAMENTS
fastify.post('/tournament/create', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { tournament_name, player_ids } = request.body
		const creator_id = request.user.id

		if (!tournament_name || !player_ids || !Array.isArray(player_ids)) {
			return reply.code(400).send({ message: "Tournament name and player IDs required" })
		}

		if (player_ids.length < 2 || player_ids.length > 5) {
			return reply.code(400).send({ message: "Tournament must have 2-5 players" })
		}

		if (!player_ids.includes(creator_id)) {
			player_ids.unshift(creator_id)
		}

		db = await openDB()
		for (const playerId of player_ids) {
			if (playerId === creator_id) continue

			const friendship = await db.get(
				`SELECT id FROM friends WHERE
				 ((requester_id = ? AND addressee_id = ?) OR
				  (requester_id = ? AND addressee_id = ?))
				 AND status = 'accepted'`,
				[creator_id, playerId, playerId, creator_id]
			)

			if (!friendship) {
				await db.close()
				return reply.code(403).send({ message: "You can only invite friends to tournament" })
			}
		}

		await db.exec(`CREATE TABLE IF NOT EXISTS tournaments (id INTEGER PRIMARY KEY AUTOINCREMENT,
		tournament_name TEXT NOT NULL,
		tournament_code TEXT UNIQUE NOT NULL,
		creator_id INTEGER NOT NULL,
		status TEXT DEFAULT 'waiting',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (creator_id) REFERENCES users(id));
		CREATE TABLE IF NOT EXISTS tournament_players (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tournament_id INTEGER NOT NULL,
		player_id INTEGER NOT NULL,
		status TEXT DEFAULT 'invited',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (tournament_id) REFERENCES tournaments(id) ON DELETE CASCADE,
		FOREIGN KEY (player_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_tournament_players ON tournament_players(tournament_id, player_id);
		`)

		const tournamentCode = Math.random().toString(36).substring(2, 9).toUpperCase()
		const result = await db.run(
			`INSERT INTO tournaments (tournament_name, tournament_code, creator_id, status, created_at)
			 VALUES (?, ?, ?, 'waiting', datetime('now'))`,
			[tournament_name, tournamentCode, creator_id]
		)

		const tournamentId = result.lastID

		await db.run(
			`INSERT INTO tournament_players (tournament_id, player_id, status)
			 VALUES (?, ?, 'accepted')`,
			[tournamentId, creator_id]
		)

		for (const playerId of player_ids) {
			if (playerId === creator_id) continue
			await db.run(
				`INSERT INTO tournament_players (tournament_id, player_id, status)
				 VALUES (?, ?, 'invited')`,
				[tournamentId, playerId]
			)
		}

		await db.close()

		return reply.code(200).send({
			message: "Tournament created",
			tournament_id: tournamentId,
			tournament_code: tournamentCode
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error creating tournament" })
	}
})

fastify.get('/tournament/invitations', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const userId = request.user.id

		db = await openDB()

		const invitations = await db.all(
			`SELECT t.id, t.tournament_name, t.tournament_code, t.created_at,
				u.login as creator_login, u.avatar as creator_avatar,
				COUNT(tp2.id) as total_players
			 FROM tournament_players tp
			 JOIN tournaments t ON tp.tournament_id = t.id
			 JOIN users u ON t.creator_id = u.id
			 LEFT JOIN tournament_players tp2 ON t.id = tp2.tournament_id
			 WHERE tp.player_id = ? AND tp.status = 'invited' AND t.status = 'waiting'
			 GROUP BY t.id`,
			[userId]
		)

		await db.close()

		return reply.send({
			invitations: invitations || []
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error fetching invitations" })
	}
})

fastify.post('/tournament/:tournamentId/accept', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { tournamentId } = request.params
		const userId = request.user.id

		db = await openDB()

		const participant = await db.get(
			`SELECT id, status FROM tournament_players
			 WHERE tournament_id = ? AND player_id = ?`,
			[tournamentId, userId]
		)

		if (!participant) {
			await db.close()
			return reply.code(404).send({ message: "You were not invited to this tournament" })
		}

		if (participant.status !== 'invited') {
			await db.close()
			return reply.code(400).send({ message: "Invalid invitation status" })
		}

		await db.run(
			`UPDATE tournament_players SET status = 'accepted'
			 WHERE tournament_id = ? AND player_id = ?`,
			[tournamentId, userId]
		)

		await db.close()

		return reply.send({ message: "Invitation accepted" })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error accepting invitation" })
	}
})

fastify.post('/tournament/:tournamentId/decline', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { tournamentId } = request.params
		const userId = request.user.id

		db = await openDB()

		await db.run(
			`UPDATE tournament_players SET status = 'declined'
			 WHERE tournament_id = ? AND player_id = ?`,
			[tournamentId, userId]
		)

		await db.close()

		return reply.send({ message: "Invitation declined" })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error declining invitation" })
	}
})

fastify.get('/tournament/:tournamentId', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { tournamentId } = request.params
		const userId = request.user.id

		if (!tournamentId) {
			return reply.code(400).send({ message: "Tournament ID is required" })
		}

		db = await openDB()

		const tournament = await db.get(
			`SELECT t.id, t.tournament_name, t.tournament_code, t.creator_id, t.status, t.created_at
			 FROM tournaments t
			 WHERE t.id = ?`,
			[tournamentId]
		)

		if (!tournament) {
			await db.close()
			return reply.code(404).send({ message: "Tournament not found" })
		}

		const participant = await db.get(
			`SELECT id, status FROM tournament_players 
			 WHERE tournament_id = ? AND player_id = ?`,
			[tournamentId, userId]
		)

		if (!participant) {
			await db.close()
			return reply.code(403).send({ message: "You don't have access to this tournament" })
		}

		const players = await db.all(
			`SELECT u.id, u.login, u.avatar, u.onlineStatus, tp.status
			 FROM tournament_players tp
			 JOIN users u ON tp.player_id = u.id
			 WHERE tp.tournament_id = ?
			 ORDER BY tp.created_at ASC`,
			[tournamentId]
		)

		const notAccepted = await db.get(
			`SELECT COUNT(*) as count FROM tournament_players 
			 WHERE tournament_id = ? AND status != 'accepted' AND status != 'declined'`,
			[tournamentId]
		)

		const allAccepted = notAccepted.count === 0

		await db.close()

		return reply.send({
			...tournament,
			players,
			userStatus: participant.status,
			allAccepted,
			isCreator: tournament.creator_id === userId
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error fetching tournament" })
	}
})

fastify.post('/tournament/:tournamentId/start', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { tournamentId } = request.params
		const userId = request.user.id

		db = await openDB()

		const tournament = await db.get(
			`SELECT creator_id, status FROM tournaments WHERE id = ?`,
			[tournamentId]
		)

		if (!tournament) {
			await db.close()
			return reply.code(404).send({ message: "Tournament not found" })
		}

		if (tournament.creator_id !== userId) {
			await db.close()
			return reply.code(403).send({ message: "Only creator can start tournament" })
		}

		if (tournament.status !== 'waiting') {
			await db.close()
			return reply.code(400).send({ message: "Tournament already started" })
		}

		const declined = await db.get(
			`SELECT COUNT(*) as count FROM tournament_players
			 WHERE tournament_id = ? AND status NOT IN ('accepted', 'declined')`,
			[tournamentId]
		)

		if (declined.count > 0) {
			await db.close()
			return reply.code(400).send({ message: "Not all players have responded" })
		}

		const declinedCount = await db.get(
			`SELECT COUNT(*) as count FROM tournament_players
			 WHERE tournament_id = ? AND status = 'declined'`,
			[tournamentId]
		)

		if (declinedCount.count > 0) {
			await db.close()
			return reply.code(400).send({ message: "Some players declined the invitation" })
		}

		await db.run(
			`UPDATE tournaments SET status = 'active' WHERE id = ?`,
			[tournamentId]
		)

		await db.close()

		return reply.send({ message: "Tournament started" })
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error starting tournament" })
	}
})

fastify.post('/tournament/:tournamentId/finish', { preHandler: [fastify.authenticate] }, async (request, reply) => {
	let db
	try {
		const { tournamentId } = request.params
		const userId = request.user.id

		if (!tournamentId) {
			return reply.code(400).send({ message: "Tournament ID is required" })
		}

		db = await openDB()

		const tournament = await db.get(
			`SELECT t.id, t.status FROM tournaments t
			 JOIN tournament_players tp ON t.id = tp.tournament_id
			 WHERE t.id = ? AND tp.player_id = ?`,
			[tournamentId, userId]
		)

		if (!tournament) {
			await db.close()
			return reply.code(404).send({ message: "Tournament not found" })
		}

		if (tournament.status !== 'finished') {
			await db.run(
				'UPDATE tournaments SET status = ? WHERE id = ?',
				['finished', tournamentId]
			)
		}

		await db.close()

		return reply.code(200).send({
			message: "Tournament finished",
			tournament_id: tournamentId
		})
	}
	catch (err) {
		if (db) await db.close()
		request.log.error(err)
		return reply.code(500).send({ message: "Error finishing tournament" })
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
