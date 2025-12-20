(() => {
	const tournamentId = new URLSearchParams(window.location.search).get('tournamentId')
	async function checkAccess(): Promise<void> {
		if (!tournamentId) {
			window.location.href = 'profile.html'
			return
		}

		try {
			const response = await fetch(`/tournament/${tournamentId}`, {
				credentials: 'include'
			})

			if (response.status === 401) {
				window.location.href = '/login.html'
				return
			}

			if (response.status === 403) {
				alert('You don\'t have access to this tournament')
				window.location.href = 'profile.html'
				return
			}

			if (response.status === 404) {
				alert('Tournament not found')
				window.location.href = 'profile.html'
				return
			}

			if (response.ok) {
				const tournament = await response.json()
				if (tournament.status === 'finished') {
					window.location.href = 'profile.html'
					return
				}
			}
			const tournamentIdEl = document.getElementById('tournamentId')
			if (tournamentIdEl) {
				tournamentIdEl.textContent = tournamentId
			}
		}
		catch (err) {
			console.error('Error checking tournament access:', err)
			window.location.href = 'profile.html'
		}
	}

	window.addEventListener('beforeunload', async () => {
		try {
			await fetch(`/tournament/${tournamentId}/finish`, {
				method: 'POST',
				credentials: 'include'
			})
		}
		catch (err) {
			console.error('Error finishing tournament:', err)
		}
	})

	document.addEventListener('DOMContentLoaded', () => {
		checkAccess()
	})
})()
