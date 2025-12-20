document.addEventListener('DOMContentLoaded', async () => {
	const isAuthenticated = await checkAuth();
	if (isAuthenticated) {
		window.location.href = '/profile.html';
	}
});
