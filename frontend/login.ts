document.addEventListener('DOMContentLoaded', () => {
	ensureAuth();
	const loginForm = document.getElementById('loginForm') as HTMLFormElement;

	if (!loginForm) {
		console.error('Login form not found');
		return;
	}

	loginForm.addEventListener('submit', async (e: Event) => {
		e.preventDefault();

		const formData = new FormData(loginForm);
		const data: Record<string, any> = {};

		formData.forEach((value, key) => {
			data[key] = value;
		});

		try {
			const res = await fetch('/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(data),
				credentials: 'include'
			});

			const result = await res.json();

			if (res.ok) {
				window.location.href = '/profile.html';
			} else {
				const messageEl = document.getElementById('message');
				if (messageEl) messageEl.textContent = result.message || 'Login failed';
			}
		}
		catch (err) {
			console.error('Login error:', err);
			const messageEl = document.getElementById('message');
			if (messageEl) messageEl.textContent = 'Server error';
		}
	});
});
