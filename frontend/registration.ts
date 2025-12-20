document.addEventListener('DOMContentLoaded', () => {
	ensureAuth();

	const registrationForm = document.getElementById('registrationForm') as HTMLFormElement;
	const messageEl = document.getElementById('message');

	registrationForm.addEventListener('submit', async (e) => {
		e.preventDefault();
		const formData = new FormData(registrationForm);
		const data: Record<string, any> = {};
		formData.forEach((value, key) => {
			data[key] = value;
		});

		try {
			const res = await fetch('/registration', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(data),
				credentials: 'include'
			});
			const result = await res.json();

			if (res.ok) {
				if (messageEl) {
					messageEl.textContent = "Registration successful!";
					messageEl.classList.remove('text-red-600');
					messageEl.classList.add('text-green-600');
				}
				registrationForm.reset();
			}
			else {
				if (messageEl) {
					messageEl.textContent = result.message;
					messageEl.classList.remove('text-green-600');
					messageEl.classList.add('text-red-600');
				}
			}
		}
		catch (err) {
			if (messageEl) {
				messageEl.textContent = "Server error";
				messageEl.classList.remove('text-green-600');
				messageEl.classList.add('text-red-600');
			}
		}
	});
});
