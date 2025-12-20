(() => {
	interface GameData {
		id: number
		player1_id: number
		player2_id: number
		player1_login: string
		player1_avatar: string
		player2_login: string
		player2_avatar: string
		status: 'waiting' | 'active' | 'finished'
		game_code: string
	}

	const gameId = new URLSearchParams(window.location.search).get('gameId')
	let gameData: GameData | null = null
	let pollInterval: number | null = null

	async function loadGameData(): Promise<void> {
		if (!gameId) {
			alert('No game ID provided')
			window.location.href = 'profile.html'
			return
		}

		try {
			const response = await fetch(`/game/${gameId}`, {
				credentials: 'include'
			})

			const data: any = await response.json()

			if (response.status === 401) {
				window.location.href = '/login.html'
				return
			}

			if (response.status === 403) {
				alert('You don\'t have access to this game')
				window.location.href = 'profile.html'
				return
			}

			if (!response.ok) {
				throw new Error(data.message || 'Failed to load game')
			}

			gameData = data

			if (gameData!.status === 'finished') {
				window.location.href = 'profile.html'
				return
			}

			document.getElementById('gameId')!.textContent = gameData!.id.toString()
			document.getElementById('player1Name')!.textContent = gameData!.player1_login
			document.getElementById('player2Name')!.textContent = gameData!.player2_login

			if (gameData!.status === 'waiting') {
				document.getElementById('waitingState')!.classList.remove('hidden')
				startPolling()
			} else if (gameData!.status === 'active') {
				startGame()
			}
		}
		catch (err) {
			console.error('Error loading game:', err)
			alert('Failed to load game')
			window.location.href = 'profile.html'
		}
	}

	function startPolling(): void {
		pollInterval = window.setInterval(async () => {
			try {
				const response = await fetch(`/game/${gameId}`, {
					credentials: 'include'
				})

				const data: GameData = await response.json()

				if (response.status === 403) {
					stopPolling()
					window.location.href = 'profile.html'
					return
				}

				if (response.ok) {
					if (data.status === 'finished') {
						stopPolling()
						window.location.href = 'profile.html'
						return
					}

					if (data.status === 'active') {
						stopPolling()
						startGame()
					}
				}
			}
			catch (err) {
				console.error('Polling error:', err)
			}
		}, 1000)
	}

	function startGame(): void {
		window.location.href = `game-play.html?gameId=${gameId}`
	}

	function stopPolling(): void {
		if (pollInterval !== null) {
			clearInterval(pollInterval)
			pollInterval = null
		}
	}

	document.addEventListener('DOMContentLoaded', () => {
		loadGameData()
	})

	window.addEventListener('beforeunload', () => {
		stopPolling()
	})
})()
