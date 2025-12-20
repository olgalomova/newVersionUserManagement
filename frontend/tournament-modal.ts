(() => {
	interface Friend {
		id: number
		login: string
		avatar: string
		onlineStatus: string
	}

	interface TournamentResponse {
		message: string
		tournament_id: number
		tournament_code: string
	}

	let selectedPlayers: Set<number> = new Set()
	let allFriends: Friend[] = []

	async function loadFriends(): Promise<void> {
		try {
			const response = await fetch('/friends', {
				credentials: 'include'
			})
			const data = await response.json()

			if (!response.ok) {
				throw new Error(data.message || 'Failed to load friends')
			}

			const friendsList = document.getElementById('friendsList') as HTMLElement
			const emptyState = document.getElementById('emptyState') as HTMLElement
			const loadingState = document.getElementById('loadingState') as HTMLElement
			const tournamentForm = document.getElementById('tournamentForm') as HTMLElement

			if (!data.friends || data.friends.length === 0) {
				emptyState.classList.remove('hidden')
				loadingState.classList.add('hidden')
				return
			}

			allFriends = data.friends
			friendsList.innerHTML = ''

			data.friends.forEach((friend: Friend) => {
				const div = document.createElement('div')
				div.className = 'friend-card bg-gray-100 hover:bg-gray-200 p-4 rounded-lg cursor-pointer transition flex items-center gap-3'
				div.dataset.friendId = friend.id.toString()
				div.innerHTML = `
				<img src="uploads/${friend.avatar || 'default.png'}" alt="${friend.login}"
				class="w-12 h-12 rounded-full object-cover">
				<div class="flex-1">
				<p class="font-semibold text-gray-900">${friend.login}</p>
				<p class="text-sm text-gray-600">${friend.onlineStatus === 'online' ? '🟢 Online' : '⚫ Offline'}</p>
				</div>
				<div class="checkbox w-5 h-5 rounded border-2 border-gray-300 flex items-center justify-center">
				<span class="hidden">✓</span>
				</div>
				`

				div.addEventListener('click', () => togglePlayer(friend.id, div))
				friendsList.appendChild(div)
			})

			loadingState.classList.add('hidden')
			tournamentForm.classList.remove('hidden')

		}
		catch (err) {
			console.error('Error loading friends:', err)
			const loadingState = document.getElementById('loadingState') as HTMLElement
			loadingState.classList.add('hidden')
			const emptyState = document.getElementById('emptyState') as HTMLElement
			emptyState.classList.remove('hidden')
			emptyState.innerHTML = `
			<p class="text-red-600 mb-4">Error loading friends: ${(err as Error).message}</p>
			<button onclick="location.reload()" class="text-blue-600 hover:text-blue-700">Try again</button>
			`
		}
	}

	function togglePlayer(friendId: number, element: HTMLElement): void {
		if (selectedPlayers.has(friendId)) {
			selectedPlayers.delete(friendId)
			element.classList.remove('ring-2', 'ring-blue-500', 'bg-blue-50')
			element.classList.add('bg-gray-100')
			const checkbox = element.querySelector('.checkbox span') as HTMLElement
			if (checkbox) checkbox.classList.add('hidden')
		}
	else {
		if (selectedPlayers.size >= 5) {
			alert('Maximum 5 players per tournament!')
			return
		}
		selectedPlayers.add(friendId)
		element.classList.remove('bg-gray-100')
		element.classList.add('bg-blue-50', 'ring-2', 'ring-blue-500')
		const checkbox = element.querySelector('.checkbox span') as HTMLElement
		if (checkbox) checkbox.classList.remove('hidden')
	}
updatePlayerCount()
	}

	function updatePlayerCount(): void {
		const countEl = document.getElementById('playerCount') as HTMLElement
		countEl.textContent = `${selectedPlayers.size}/5`

		const preview = document.getElementById('selectedPlayersPreview') as HTMLElement
		const list = document.getElementById('selectedPlayersList') as HTMLElement

		if (selectedPlayers.size === 0) {
			preview.classList.add('hidden')
			return
		}

		preview.classList.remove('hidden')
		list.innerHTML = ''

		selectedPlayers.forEach(friendId => {
			const friend = allFriends.find(f => f.id === friendId)
			if (friend) {
				const tag = document.createElement('div')
				tag.className = 'bg-blue-200 text-blue-900 px-3 py-1 rounded-full text-sm font-semibold'
				tag.textContent = friend.login
				list.appendChild(tag)
			}
		})
	}

	async function createTournament(): Promise<void> {
		const errorEl = document.getElementById('errorMessage') as HTMLElement
		errorEl.textContent = ''

		if (selectedPlayers.size < 2) {
			errorEl.textContent = 'Select at least 2 players'
			return
		}

		const nameInput = document.getElementById('tournamentName') as HTMLInputElement
		let tournamentName = nameInput?.value?.trim() || ''

		if (!tournamentName) {
			const timestamp = new Date().toLocaleString('en-US', { 
				month: 'short', 
				day: 'numeric', 
				hour: '2-digit', 
				minute: '2-digit' 
			})
			tournamentName = `Tournament ${timestamp}`
		}

		try {
			const response = await fetch('/tournament/create', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					tournament_name: tournamentName,
					player_ids: Array.from(selectedPlayers)
				}),
				credentials: 'include'
			})

			const data: TournamentResponse = await response.json()

			if (!response.ok) {
				errorEl.textContent = (data as any).message || 'Failed to create tournament'
				return
			}
			window.location.href = `tournament.html?tournamentId=${data.tournament_id}`
		}
		catch (err) {
			console.error('Error creating tournament:', err)
			errorEl.textContent = 'Error creating tournament'
		}
	}

	document.getElementById('cancelBtn')?.addEventListener('click', () => {
		window.history.back()
	})

	document.getElementById('createBtn')?.addEventListener('click', createTournament)

	document.addEventListener('DOMContentLoaded', () => {
		loadFriends()
	})
})();
