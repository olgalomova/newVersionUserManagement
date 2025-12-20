(() => {
	interface Player {
		id: number
		login: string
		avatar: string
		onlineStatus: string
		status: string
	}

	interface TournamentData {
		id: number
		tournament_name: string
		tournament_code: string
		creator_id: number
		status: string
		userStatus: string
		allAccepted: boolean
		isCreator: boolean
		created_at: string
		players: Player[]
	}

	const tournamentId = new URLSearchParams(window.location.search).get('tournamentId')
	let tournamentData: TournamentData | null = null
	let pollInterval: number | null = null

	async function loadTournamentData(): Promise<void> {
		if (!tournamentId) {
			alert('No tournament ID provided');
			window.location.href = 'profile.html';
			return;
		}

		try {
			const response = await fetch(`/tournament/${tournamentId}`, {
				credentials: 'include'
			});

			const data: any = await response.json();

			if (response.status === 401) {
				window.location.href = '/login.html'
				return
			}

			if (response.status === 403) {
				alert('You don\'t have access to this tournament')
				window.location.href = 'profile.html'
				return
			}

			if (!response.ok) {
				throw new Error(data.message || 'Failed to load tournament');
			}

			tournamentData = data;

			if (tournamentData!.status === 'finished') {
				window.location.href = 'profile.html'
				return
			}

			document.getElementById('tournamentCode')!.textContent = tournamentData!.tournament_code;
			document.getElementById('tournamentName')!.textContent = tournamentData!.tournament_name;

			renderPlayers();

			if (tournamentData!.isCreator && tournamentData!.allAccepted) {
				showStartButton();
			}

			startPolling();

		}
		catch (err) {
			console.error('Error loading tournament:', err);
			alert('Failed to load tournament');
			window.location.href = 'profile.html';
		}
	}

	function renderPlayers(): void {
		const playersList = document.getElementById('playersList')!;
		playersList.innerHTML = '';

		if (!tournamentData?.players) return;

		tournamentData.players.forEach(player => {
			const statusIcon = player.status === 'accepted' ? '✓' : player.status === 'declined' ? '✗' : '⏳';
			const statusColor = player.status === 'accepted' ? 'green' : player.status === 'declined' ? 'red' : 'yellow';

			const card = document.createElement('div');
			card.className = 'bg-gray-50 p-4 rounded-lg border border-gray-200 transition-all';
			card.innerHTML = `
			<img src="uploads/${player.avatar || 'default.png'}" alt="${player.login}"
			class="w-12 h-12 rounded-full object-cover mx-auto mb-2">
			<p class="font-semibold text-gray-900 text-sm">${player.login}</p>
			<p class="text-xs text-gray-500 mt-1">${player.onlineStatus === 'online' ? '🟢 Online' : '⚫ Offline'}</p>
			<p class="text-xs bg-${statusColor}-100 text-${statusColor}-700 mt-2 px-2 py-1 rounded font-semibold">
			${statusIcon} ${player.status.toUpperCase()}
			</p>
			`;
			playersList.appendChild(card);
		});
	}

	function showStartButton(): void {
		const startBtn = document.getElementById('startBtn') as HTMLButtonElement;
		if (startBtn) {
			startBtn.classList.remove('hidden');
			startBtn.addEventListener('click', startTournament);
		}
	}

	async function startTournament(): Promise<void> {
		try {
			const response = await fetch(`/tournament/${tournamentId}/start`, {
				method: 'POST',
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(data.message || 'Failed to start tournament');
			}

			startGame();

		}
		catch (err) {
			console.error('Error starting tournament:', err);
			alert(`Error: ${(err as Error).message}`);
		}
	}

	function startGame(): void {
		document.getElementById('waitingState')!.classList.add('hidden');
		document.getElementById('activeState')!.classList.remove('hidden');

		setTimeout(() => {
			window.location.href = `tournament-game.html?tournamentId=${tournamentId}`;
		}, 2000);
	}

	function startPolling(): void {
		pollInterval = window.setInterval(async () => {
			try {
				const response = await fetch(`/tournament/${tournamentId}`, {
					credentials: 'include'
				});

				const data: TournamentData = await response.json();
				if (response.status === 403) {
					stopPolling()
					window.location.href = 'profile.html'
					return
				}

				if (response.ok) {
					tournamentData = data;
					renderPlayers();
					if (data.status === 'finished') {
						stopPolling()
						window.location.href = 'profile.html'
						return
					}
					if (tournamentData!.isCreator && tournamentData!.allAccepted) {
						showStartButton();
					}
					if (data.status === 'active') {
						stopPolling();
						startGame();
					}
				}
			}
			catch (err) {
				console.error('Polling error:', err);
			}
		}, 2000);
	}

	function stopPolling(): void {
		if (pollInterval !== null) {
			clearInterval(pollInterval)
			pollInterval = null
		}
	}

	document.addEventListener('DOMContentLoaded', () => {
		loadTournamentData()
	})

	window.addEventListener('beforeunload', () => {
		stopPolling()
	})

})();
