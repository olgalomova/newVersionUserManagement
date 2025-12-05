import sqlite3 from 'sqlite3'
import { open } from 'sqlite'

// Функция для подключения к базе
export async function openDB() {
	const dbPath = process.env.DB_PATH || '/app/data/users.db'
	const db = await open({
		filename: dbPath,
		driver: sqlite3.Database
	})

	// Создаём таблицу, если её нет (на случай если init-db не выполнился)
	await db.exec(`CREATE TABLE IF NOT EXISTS users (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    login TEXT UNIQUE NOT NULL,
	    email TEXT UNIQUE NOT NULL,
	    password TEXT NOT NULL,
	    avatar TEXT
	)`)

	return db
}
