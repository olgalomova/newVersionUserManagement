async function checkAuth(): Promise<boolean> {
	try {
		const res = await fetch('/profile', { credentials: 'include' });
		return res.ok;
	}
	catch (err) {
		return false;
	}
}

async function ensureAuth(): Promise<void> {
	const isAuthenticated = await checkAuth();
	const currentPage = window.location.pathname;

	const publicPages = ['/login.html', '/registration.html', '/index.html', '/'];

	const isPublicPage = publicPages.some(page => currentPage.endsWith(page));

	if (!isPublicPage && !isAuthenticated) {
		window.location.href = '/login.html';
	}
	else if (isAuthenticated && (currentPage.endsWith('/login.html') || currentPage.endsWith('/registration.html'))) {
		window.location.href = '/profile.html';
	}
}

async function logout(): Promise<void> {
	try {
		await fetch('/logout', { method: 'POST', credentials: 'include' });
		window.location.href = '/login.html';
	}
	catch (err) {
		console.error('Logout error:', err);
		window.location.href = '/login.html';
	}
}

document.addEventListener('DOMContentLoaded', () => {
	ensureAuth();
});
