(() => {
	const gameId = new URLSearchParams(window.location.search).get('gameId')

	async function checkAccess(): Promise<void> {
		if (!gameId) {
			window.location.href = 'profile.html'
			return
		}

		try {
			const response = await fetch(`/game/${gameId}`, {
				credentials: 'include'
			})

			if (response.status === 401) {
				window.location.href = '/login.html'
				return
			}

			if (response.status === 403) {
				alert('You don\'t have access to this game')
				window.location.href = 'profile.html'
				return
			}

			if (response.status === 404) {
				alert('Game not found')
				window.location.href = 'profile.html'
				return
			}

			if (response.ok) {
				const game = await response.json()
				if (game.status === 'finished') {
					window.location.href = 'profile.html'
					return
				}
			}
			const gameIdEl = document.getElementById('gameId')
			if (gameIdEl) {
				gameIdEl.textContent = gameId
			}
		}
		catch (err) {
			console.error('Error checking game access:', err)
			window.location.href = 'profile.html'
		}
	}

	window.addEventListener('beforeunload', async () => {
		try {
			await fetch(`/game/${gameId}/finish`, {
				method: 'POST',
				credentials: 'include'
			})
		}
		catch (err) {
			console.error('Error finishing game:', err)
		}
	})

	document.addEventListener('DOMContentLoaded', () => {
		checkAccess()
	})
})()
