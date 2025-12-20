import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'fs'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

async function initDatabase() {
	try {
		const dbPath = process.env.DB_PATH || path.join(__dirname, '../data/users.db')

		if (fs.existsSync(dbPath)) {
			console.log(`Database already exists at ${dbPath}, skipping init`)
			process.exit(0)
		}
		console.log(`Initializing database at: ${dbPath}`)

		const db = await open({
			filename: dbPath,
			driver: sqlite3.Database
		})

		//table users
		await db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,
		login TEXT UNIQUE,
		email TEXT UNIQUE NOT NULL,
		password TEXT,
		avatar TEXT,
		wins INTEGER DEFAULT 0,
		losses INTEGER DEFAULT 0,
		draws INTEGER DEFAULT 0,
		total_games INTEGER DEFAULT 0,
		onlineStatus TEXT NOT NULL,
		oauth_provider TEXT,
		oauth_id TEXT
		);`)
		console.log('Table "users" created')

		//table friends
		await db.exec(`CREATE TABLE IF NOT EXISTS friends (id INTEGER PRIMARY KEY AUTOINCREMENT,
		requester_id INTEGER NOT NULL,
		addressee_id INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (requester_id) REFERENCES users(id),
		FOREIGN KEY (addressee_id) REFERENCES users(id)
		);`)

		console.log('Table "friends" created')

		// table match_history (unused)
		await db.exec(`CREATE TABLE IF NOT EXISTS match_history (id INTEGER PRIMARY KEY AUTOINCREMENT,
		player1_id INTEGER NOT NULL,
		player2_id INTEGER NOT NULL,
		winner_id INTEGER,
		played_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		score_player1 INTEGER DEFAULT 0,
		score_player2 INTEGER DEFAULT 0,
		details TEXT,
		FOREIGN KEY (player1_id) REFERENCES users(id),
		FOREIGN KEY (player2_id) REFERENCES users(id),
		FOREIGN KEY (winner_id) REFERENCES users(id)
		);`)

		await db.exec(`CREATE TABLE IF NOT EXISTS games (id INTEGER PRIMARY KEY AUTOINCREMENT,
		player1_id INTEGER NOT NULL,
		player2_id INTEGER NOT NULL,
		status TEXT DEFAULT 'waiting',
		game_code TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (player1_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (player2_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_games_players ON games(player1_id, player2_id);`)

		console.log('Table "games" created')

		await db.exec(`CREATE TABLE IF NOT EXISTS tournaments (id INTEGER PRIMARY KEY AUTOINCREMENT,
		tournament_name TEXT NOT NULL,
		tournament_code TEXT UNIQUE NOT NULL,
		creator_id INTEGER NOT NULL,
		status TEXT DEFAULT 'waiting',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (creator_id) REFERENCES users(id)
		);`)

		console.log('Table "tournaments" created')

		// table tournament_players
		await db.exec(`CREATE TABLE IF NOT EXISTS tournament_players (id INTEGER PRIMARY KEY AUTOINCREMENT,
		tournament_id INTEGER NOT NULL,
		player_id INTEGER NOT NULL,
		status TEXT DEFAULT 'joined',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (tournament_id) REFERENCES tournaments(id) ON DELETE CASCADE,
		FOREIGN KEY (player_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_tournament_players ON tournament_players(tournament_id, player_id);`)

		console.log('Table "tournament_players" created')
		await db.close()
		process.exit(0)
	}
	catch (err) {
		console.error('Database initialization error:', err)
		process.exit(1)
	}
}

initDatabase()
