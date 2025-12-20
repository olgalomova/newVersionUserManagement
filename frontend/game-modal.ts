(() => {
	interface Friend {
		id: number
		login: string
		avatar: string
		onlineStatus: string
	}

	interface GameResponse {
		message: string
		game_id: number
		game_code: string
	}

	let selectedFriendId: number | null = null

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

			if (!data.friends || data.friends.length === 0) {
				emptyState.classList.remove('hidden')
				friendsList.classList.add('hidden')
				loadingState.classList.add('hidden')
				return
			}

			friendsList.innerHTML = ''
			data.friends.forEach((friend: Friend) => {
				const div = document.createElement('div')
				div.className = 'friend-card bg-gray-100 hover:bg-gray-200 p-4 rounded-lg cursor-pointer transition flex items-center gap-3'
				div.innerHTML = `
				<img src="uploads/${friend.avatar || 'default.png'}" alt="${friend.login}"
				class="w-12 h-12 rounded-full object-cover">
				<div class="flex-1">
				<p class="font-semibold text-gray-900">${friend.login}</p>
				<p class="text-sm text-gray-600">${friend.onlineStatus === 'online' ? '🟢 Online' : '⚫ Offline'}</p>
				</div>
				`

				div.addEventListener('click', () => selectFriend(friend.id, div))
				friendsList.appendChild(div)
			})

			loadingState.classList.add('hidden')
			friendsList.classList.remove('hidden')
		}
		catch (err) {
			console.error('Error loading friends:', err)
			const loadingState = document.getElementById('loadingState') as HTMLElement
			const emptyState = document.getElementById('emptyState') as HTMLElement
			loadingState.classList.add('hidden')
			emptyState.classList.remove('hidden')
			emptyState.innerHTML = `
			<p class="text-red-600 mb-4">Error loading friends: ${(err as Error).message}</p>
			<button onclick="location.reload()" class="text-blue-600 hover:text-blue-700">Try again</button>
			`
		}
	}

	function selectFriend(friendId: number, element: HTMLElement): void {
		document.querySelectorAll('.friend-card').forEach(card => {
			card.classList.remove('ring-2', 'ring-blue-500', 'bg-blue-50')
			card.classList.add('bg-gray-100')
		})

		element.classList.remove('bg-gray-100')
		element.classList.add('bg-blue-50', 'ring-2', 'ring-blue-500')
		selectedFriendId = friendId
	}

	async function createGame(): Promise<void> {
		if (!selectedFriendId) {
			alert('Please select a friend')
			return
		}

		try {
			const response = await fetch('/game/create', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ opponent_id: selectedFriendId }),
				credentials: 'include'
			})

			const data: GameResponse = await response.json()

			if (!response.ok) {
				alert((data as any).message || 'Failed to create game')
				return
			}

			// Переходим на страницу ожидания соперника
			window.location.href = `game.html?gameId=${data.game_id}`
		}
		catch (err) {
			console.error('Error creating game:', err)
			alert('Error creating game')
		}
	}

	document.getElementById('cancelBtn')?.addEventListener('click', () => {
		window.history.back()
	})

	document.getElementById('playBtn')?.addEventListener('click', createGame)

	document.addEventListener('DOMContentLoaded', () => {
		loadFriends()
	})
})()
