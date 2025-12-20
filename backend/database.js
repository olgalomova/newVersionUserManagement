import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export async function openDB() {
	const dbPath = process.env.DB_PATH || path.join(__dirname, '../data/users.db')
	console.log('Opening DB at:', dbPath)

	try {
		const db = await open({
			filename: dbPath,
			driver: sqlite3.Database
		})
		console.log('Database connected successfully')
		return db
	}
	catch (err) {
		console.error('Failed to open database:', err)
		throw err
	}
}
