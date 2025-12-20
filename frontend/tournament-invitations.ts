(() => {
	interface Invitation {
		id: number
		tournament_name: string
		tournament_code: string
		creator_login: string
		creator_avatar: string
		total_players: number
		created_at: string
	}

	async function loadInvitations(): Promise<void> {
		try {
			const response = await fetch('/tournament/invitations', {
				credentials: 'include'
			})

			const data = await response.json()

			if (!response.ok) {
				throw new Error(data.message || 'Failed to load invitations')
			}

			const invitations: Invitation[] = data.invitations || []
			const loadingState = document.getElementById('loadingState') as HTMLElement
			const invitationsList = document.getElementById('invitationsList') as HTMLElement
			const emptyState = document.getElementById('emptyState') as HTMLElement
			const closeBtn = document.getElementById('closeBtn') as HTMLElement

			loadingState.classList.add('hidden')

			if (invitations.length === 0) {
				emptyState.classList.remove('hidden')
				closeBtn.classList.remove('hidden')
				return
			}

			invitationsList.classList.remove('hidden')
			closeBtn.classList.remove('hidden')
			invitationsList.innerHTML = ''

			invitations.forEach((invitation: Invitation) => {
				const card = document.createElement('div')
				card.className = 'bg-blue-50 border-2 border-blue-200 rounded-lg p-4'
				card.innerHTML = `
				<div class="flex items-start gap-4 mb-4">
				<img src="uploads/${invitation.creator_avatar || 'default.png'}" 
				alt="${invitation.creator_login}"
				class="w-12 h-12 rounded-full object-cover">
				<div class="flex-1">
				<p class="font-semibold text-gray-900">${invitation.creator_login}</p>
				<p class="text-sm text-gray-600">invited you to a tournament</p>
				</div>
				</div>

				<div class="bg-white rounded-lg p-3 mb-4">
				<p class="text-sm text-gray-600">Tournament Name</p>
				<p class="font-semibold text-gray-900">${invitation.tournament_name}</p>
				<p class="text-xs text-gray-500 mt-2">Code: <span class="font-mono">${invitation.tournament_code}</span></p>
				<p class="text-xs text-gray-500">Players: ${invitation.total_players}</p>
				</div>

				<div class="flex gap-3">
				<button class="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg font-semibold transition accept-btn"
				data-tournament-id="${invitation.id}">
				✓ Accept
				</button>
				<button class="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg font-semibold transition decline-btn"
				data-tournament-id="${invitation.id}">
				✗ Decline
				</button>
				</div>
				`

				const acceptBtn = card.querySelector('.accept-btn') as HTMLButtonElement
				const declineBtn = card.querySelector('.decline-btn') as HTMLButtonElement

				acceptBtn.addEventListener('click', () => handleInvitation(invitation.id, 'accept', card))
				declineBtn.addEventListener('click', () => handleInvitation(invitation.id, 'decline', card))

				invitationsList.appendChild(card)
			})

		}
		catch (err) {
			console.error('Error loading invitations:', err)
			const loadingState = document.getElementById('loadingState') as HTMLElement
			loadingState.classList.add('hidden')
			const emptyState = document.getElementById('emptyState') as HTMLElement
			emptyState.classList.remove('hidden')
			emptyState.innerHTML = `
			<p class="text-red-600 mb-4">Error: ${(err as Error).message}</p>
			<button onclick="location.reload()" class="text-blue-600 hover:text-blue-700">Try again</button>
			`
		}
	}

	async function handleInvitation(tournamentId: number, action: 'accept' | 'decline', cardElement: HTMLElement): Promise<void> {
		try {
			const endpoint = action === 'accept' 
				? `/tournament/${tournamentId}/accept` 
				: `/tournament/${tournamentId}/decline`

				const response = await fetch(endpoint, {
					method: 'POST',
					credentials: 'include'
				})

				if (!response.ok) {
					const data = await response.json()
					throw new Error(data.message || `Failed to ${action} invitation`)
				}

				cardElement.style.opacity = '0'
				cardElement.style.transform = 'scale(0.95)'
				cardElement.style.transition = 'all 0.3s ease'

				setTimeout(() => {
					cardElement.remove()
					const invitationsList = document.getElementById('invitationsList') as HTMLElement
					if (invitationsList.children.length === 0) {
						invitationsList.classList.add('hidden')
						const emptyState = document.getElementById('emptyState') as HTMLElement
						emptyState.classList.remove('hidden')
					}
				}, 300)
				if (action === 'accept') {
					setTimeout(() => {
						window.location.href = `tournament.html?tournamentId=${tournamentId}`
					}, 500)
				}

		}
		catch (err) {
			console.error(`Error ${action}ing invitation:`, err)
			alert(`Error: ${(err as Error).message}`)
		}
	}

	document.addEventListener('DOMContentLoaded', () => {
		loadInvitations()

		const closeModal = document.getElementById('closeModal') as HTMLElement
		const closeBtn = document.getElementById('closeBtn') as HTMLElement

		closeModal.addEventListener('click', () => window.history.back())
		closeBtn.addEventListener('click', () => window.history.back())
	})
})()
