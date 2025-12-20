let userId: string | null = null;
let isSubmitting = false;

function updateGameStats(data: any): void {
	const wins = data.wins || 0;
	const losses = data.losses || 0;
	const draws = data.draws || 0;
	const totalGames = data.total_games || 0;

	const winsEl = document.getElementById('winsCount');
	const lossesEl = document.getElementById('lossesCount');
	const drawsEl = document.getElementById('drawsCount');
	const totalEl = document.getElementById('totalGamesCount');
	const winRateEl = document.getElementById('winRate');

	if (winsEl) winsEl.textContent = wins.toString();
	if (lossesEl) lossesEl.textContent = losses.toString();
	if (drawsEl) drawsEl.textContent = draws.toString();
	if (totalEl) totalEl.textContent = totalGames.toString();

	const winRate = totalGames > 0 ? Math.round((wins / totalGames) * 100) : 0;
	if (winRateEl) winRateEl.textContent = winRate + '%';
}

async function loadProfile(): Promise<void> {
	try {
		const res = await fetch('/profile', { credentials: 'include' });
		if (!res.ok) {
			window.location.href = '/login.html';
			return;
		}
		const data = await res.json();
		userId = data.id;

		const welcomeEl = document.getElementById('Welcome');
		if (welcomeEl) welcomeEl.textContent = "Welcome, " + data.login + "!";

		const avatarEl = document.getElementById('avatarImg') as HTMLImageElement;
		if (avatarEl) {
			avatarEl.src = data.avatar
				? '/uploads/' + encodeURIComponent(data.avatar)
				: '/uploads/default.png';
		}

		const loginInput = document.getElementById('loginInput') as HTMLInputElement;
		const emailInput = document.getElementById('emailInput') as HTMLInputElement;

		if (loginInput) loginInput.value = data.login;
		if (emailInput) emailInput.value = data.email;
		updateGameStats(data);

		await checkTournamentInvitations();

		document.body.classList.remove('hidden');
	}
	catch (err) {
		console.error('Error loading profile:', err);
		window.location.href = '/login.html';
	}
}

async function handlePlayGame(): Promise<void> {
	try {
		const pendingResponse = await fetch('/game-pending', {
			credentials: 'include'
		});

		if (pendingResponse.ok) {
			const pendingGame: any = await pendingResponse.json();

			const accept = confirm(`${pendingGame.player1_login} invited you. Do you want to accept?`);

			if (accept) {
				const acceptResponse = await fetch(`/game/${pendingGame.id}/accept`, {
					method: 'POST',
					credentials: 'include'
				});

				if (acceptResponse.ok) {
					window.location.href = `game.html?gameId=${pendingGame.id}`;
					return;
				}
				else {
					const error = await acceptResponse.json();
					alert(`Error: ${error.message || 'Failed to accept game'}`);
				}
			}
			return;
		}
		window.location.href = 'game-modal.html';

	}
	catch (err) {
		console.log('Error in handlePlayGame:', err);
		window.location.href = 'game-modal.html';
	}
}

async function checkTournamentInvitations(): Promise<void> {
	try {
		const response = await fetch('/tournament/invitations', {
			credentials: 'include'
		})

		const data = await response.json()

		if (response.ok && data.invitations && data.invitations.length > 0) {
			const notificationEl = document.createElement('div')
			notificationEl.className = 'fixed top-4 right-4 bg-blue-600 text-white px-6 py-4 rounded-lg shadow-lg flex items-center gap-4 z-40 animate-pulse'
			notificationEl.innerHTML = `
			<span class="text-lg">🎮 You have ${data.invitations.length} tournament invitation(s)!</span>
			<button onclick="window.location.href='tournament-invitations.html'" class="bg-white text-blue-600 px-4 py-2 rounded font-semibold hover:bg-gray-100 transition">
			View
			</button>
			`
			document.body.appendChild(notificationEl)
			const playTournamentBtn = document.getElementById('playTournamentBtn') as HTMLButtonElement
			if (playTournamentBtn) {
				const badge = document.createElement('span')
				badge.className = 'absolute top-0 right-0 bg-red-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold'
				badge.textContent = data.invitations.length.toString()
				playTournamentBtn.style.position = 'relative'
				playTournamentBtn.appendChild(badge)
			}
		}
	}
	catch (err) {
		console.error('Error checking invitations:', err)
	}
}

async function handlePlayTournament(): Promise<void> {
	try {
		const response = await fetch('/tournament/invitations', {
			credentials: 'include'
		})

		const data = await response.json()

		if (response.ok && data.invitations && data.invitations.length > 0) {
			showTournamentInvitationsModal(data.invitations)
		}
		else {
			window.location.href = 'tournament-modal.html'
		}
	}
	catch (err) {
		console.error('Error checking invitations:', err)
		window.location.href = 'tournament-modal.html'
	}
}

function showTournamentInvitationsModal(invitations: any[]): void {
	const modal = document.createElement('div')
	modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50'
	modal.id = 'invitationsModal'

	let invitationsHTML = invitations.map((inv: any) => `
					      <div class="bg-blue-50 border-2 border-blue-200 rounded-lg p-4 mb-4">
					      <div class="flex items-center gap-3 mb-4">
					      <img src="uploads/${inv.creator_avatar || 'default.png'}" alt="${inv.creator_login}"
					      class="w-12 h-12 rounded-full object-cover">
					      <div>
					      <p class="font-semibold text-gray-900">${inv.creator_login}</p>
					      <p class="text-sm text-gray-600">invited you to tournament</p>
					      </div>
					      </div>
					      <div class="bg-white rounded-lg p-3 mb-4">
					      <p class="font-semibold text-gray-900">${inv.tournament_name}</p>
					      <p class="text-xs text-gray-500 mt-1">Code: <span class="font-mono">${inv.tournament_code}</span></p>
					      <p class="text-xs text-gray-500">Players: ${inv.total_players}</p>
					      </div>
					      <div class="flex gap-3">
					      <button onclick="acceptInvitation(${inv.id})" class="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg font-semibold transition">
					      ✓ Accept
					      </button>
					      <button onclick="declineInvitation(${inv.id})" class="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg font-semibold transition">
					      ✗ Decline
					      </button>
					      </div>
					      </div>
					      `).join('')

					      modal.innerHTML = `
					      <div class="bg-white rounded-2xl p-8 w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto">
					      <div class="flex items-center justify-between mb-6">
					      <h2 class="text-3xl font-bold">🎮 Tournament Invitations</h2>
					      <button onclick="document.getElementById('invitationsModal').remove()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
					      </div>
					      ${invitationsHTML}
					      <div class="flex gap-3 mt-6">
					      <button onclick="window.location.href='tournament-modal.html'" class="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-lg font-semibold transition">
					      Create Tournament
					      </button>
					      <button onclick="document.getElementById('invitationsModal').remove()" class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-900 py-3 rounded-lg font-semibold transition">
					      Close
					      </button>
					      </div>
					      </div>
					      `

					      document.body.appendChild(modal)
}

async function acceptInvitation(tournamentId: number): Promise<void> {
	try {
		const response = await fetch(`/tournament/${tournamentId}/accept`, {
			method: 'POST',
			credentials: 'include'
		})

		if (response.ok) {
			// Закрываем модалку и переходим на турнир
			const modal = document.getElementById('invitationsModal')
			if (modal) modal.remove()
				window.location.href = `tournament.html?tournamentId=${tournamentId}`
		}
		else {
			const data = await response.json()
			alert(`Error: ${data.message || 'Failed to accept invitation'}`)
		}
	}
	catch (err) {
		console.error('Error accepting invitation:', err)
		alert('Error accepting invitation')
	}
}

async function declineInvitation(tournamentId: number): Promise<void> {
	try {
		const response = await fetch(`/tournament/${tournamentId}/decline`, {
			method: 'POST',
			credentials: 'include'
		})

		if (response.ok) {
			const modal = document.getElementById('invitationsModal')
			if (modal) modal.remove()
				const checkResponse = await fetch('/tournament/invitations', {
					credentials: 'include'
				})
				const data = await checkResponse.json()

				if (data.invitations && data.invitations.length > 0) {
					showTournamentInvitationsModal(data.invitations)
				}
				else {
					window.location.href = 'tournament-modal.html'
				}
		}
		else {
			const data = await response.json()
			alert(`Error: ${data.message || 'Failed to decline invitation'}`)
		}
	}
	catch (err) {
		console.error('Error declining invitation:', err)
		alert('Error declining invitation')
	}
}

document.addEventListener('DOMContentLoaded', () => {
	loadProfile();
	const playOneVOneBtn = document.getElementById('playOneVOneBtn') as HTMLButtonElement;
	if (playOneVOneBtn) {
		playOneVOneBtn.addEventListener('click', handlePlayGame);
	}

	const playTournamentBtn = document.getElementById('playTournamentBtn') as HTMLButtonElement;
	if (playTournamentBtn) {
		playTournamentBtn.addEventListener('click', handlePlayTournament);
	}

	const editForm = document.getElementById('editForm') as HTMLFormElement | null;
	if (editForm) {
		editForm.addEventListener('submit', async (e: Event) => {
			e.preventDefault();
			if (isSubmitting) return;
			isSubmitting = true;

			try {
				const loginInput = document.getElementById('loginInput') as HTMLInputElement;
				const emailInput = document.getElementById('emailInput') as HTMLInputElement;
				const passwordInput = document.getElementById('passwordInput') as HTMLInputElement;

				const body = {
					login: loginInput?.value || '',
					email: emailInput?.value || '',
					password: passwordInput?.value || ''
				};

				const res = await fetch('/profile', {
					method: 'PUT',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify(body),
					credentials: 'include'
				});

				const msg = await res.json();
				const messageEl = document.getElementById('editMessage');
				if (messageEl) messageEl.textContent = msg.message || 'Update failed';

				if (res.ok) {
					await loadProfile();
				}
			}
			catch (err) {
				console.error('Profile update error:', err);
				const messageEl = document.getElementById('editMessage');
				if (messageEl) messageEl.textContent = 'Error updating profile';
			}
			finally {
				isSubmitting = false;
			}
		});
	}

	const avatarForm = document.getElementById('avatarForm') as HTMLFormElement | null;
	if (avatarForm) {
		avatarForm.addEventListener('submit', async (e: Event) => {
			e.preventDefault();
			if (isSubmitting) return;
			isSubmitting = true;

			try {
				const fileInput = (e.target as HTMLFormElement).querySelector('input[name="avatar"]') as HTMLInputElement;
				const file = fileInput?.files?.[0];
				if (!file) {
					const msgEl = document.getElementById('avatarMessage');
					if (msgEl) msgEl.textContent = 'Please select a file';
					return;
				}

				if (file.size > 5 * 1024 * 1024) {
					const msgEl = document.getElementById('avatarMessage');
					if (msgEl) msgEl.textContent = 'File too large! Max 5MB';
					return;
				}

				const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
				if (!allowedTypes.includes(file.type)) {
					const msgEl = document.getElementById('avatarMessage');
					if (msgEl) msgEl.textContent = 'Invalid file type! Only JPEG, PNG, WebP allowed';
					return;
				}

				const formData = new FormData();
				formData.append('avatar', file);

				const res = await fetch('/avatar', {
					method: 'POST',
					body: formData,
					credentials: 'include'
				});

				const msg = await res.json();
				const msgEl = document.getElementById('avatarMessage');
				if (msgEl) msgEl.textContent = msg.message || 'Upload failed';

				if (res.ok) {
					await loadProfile();
					fileInput.value = '';
				}
			}
			catch (err) {
				console.error('Avatar upload error:', err);
				const msgEl = document.getElementById('avatarMessage');
				if (msgEl) msgEl.textContent = 'Error uploading avatar';
			}
			finally {
				isSubmitting = false;
			}
		});
	}

	const deleteAvatarBtn = document.getElementById('deleteAvatarBtn');
	if (deleteAvatarBtn) {
		deleteAvatarBtn.addEventListener('click', async () => {
			if (!confirm('Delete your avatar?')) return;

			try {
				const res = await fetch('/avatar', {
					method: 'DELETE',
					credentials: 'include'
				});

				const msg = await res.json();
				const msgEl = document.getElementById('avatarMessage');
				if (msgEl) msgEl.textContent = msg.message || 'Delete failed';

				if (res.ok) {
					await loadProfile();
				}
			}
			catch (err) {
				console.error('Avatar delete error:', err);
				const msgEl = document.getElementById('avatarMessage');
				if (msgEl) msgEl.textContent = 'Error deleting avatar';
			}
		});
	}

	const deleteProfileBtn = document.getElementById('deleteProfileBtn');
	if (deleteProfileBtn) {
		deleteProfileBtn.addEventListener('click', async () => {
			if (!confirm('Are you sure you want to delete your profile? This cannot be undone.')) {
				return;
			}

			try {
				const res = await fetch('/profile', {
					method: 'DELETE',
					credentials: 'include'
				});

				if (res.ok) {
					window.location.href = '/';
				} else {
					alert('Failed to delete profile');
				}
			}
			catch (err) {
				console.error('Profile delete error:', err);
				alert('Error deleting profile');
			}
		});
	}

	const logoutBtn = document.getElementById('logoutBtn');
	if (logoutBtn) {
		logoutBtn.addEventListener('click', async () => {
			try {
				await fetch('/logout', {
					method: 'POST',
					credentials: 'include'
				});
				window.location.href = '/login.html';
			}
			catch (err) {
				console.error('Logout error:', err);
				window.location.href = '/login.html';
			}
		});
	}
});
