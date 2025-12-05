import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'path'

async function initDatabase() {
	try {
		const dbPath = process.env.DB_PATH || '/app/data/users.db'

		console.log(`Initializing database at: ${dbPath}`)

		const db = await open({
			filename: dbPath,
			driver: sqlite3.Database
		})

		// Создаём таблицу users
		await db.exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		login TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		avatar TEXT)`)

		console.log('Database initialized successfully')
		console.log('Table "users" created')

		await db.close()
		process.exit(0)
	}
	catch (err) {
		console.error('Database initialization error:', err)
		process.exit(1)
	}
}

initDatabase()
