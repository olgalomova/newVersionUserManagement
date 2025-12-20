document.addEventListener("DOMContentLoaded", () => {
	const requestsContainer = document.getElementById("requestsContainer") as HTMLElement;
	const emptyMessage = document.getElementById("emptyMessage") as HTMLElement;
	loadRequests();

	async function loadRequests() {
		try {
			emptyMessage.textContent = "Loading...";

			const res = await fetch("/friend-requests", {
				credentials: "include"
			});

			const data = await res.json();

			if (!res.ok) {
				emptyMessage.textContent = data.message || "Error loading requests";
				return;
			}

			if (data.requests.length === 0) {
				emptyMessage.textContent = "No friend requests.";
				requestsContainer.innerHTML = "";
				return;
			}

			emptyMessage.textContent = "";
			requestsContainer.innerHTML = "";

			data.requests.forEach((req: any) => {
				const card = document.createElement("div");
				card.className = "flex items-center justify-between p-4 bg-gray-100 rounded-xl mb-3";

				card.innerHTML = `
				<div class="flex items-center gap-3">
				<img src="/uploads/${req.avatar ? req.avatar : 'default.png'}"
				class="w-12 h-12 rounded-full object-cover">
				<div>
				<p class="font-semibold">${req.login}</p>
				<p class="text-gray-500 text-sm">${req.email}</p>
				</div>
				</div>
				<div class="flex gap-2">
				<button class="bg-green-600 text-white px-3 py-1 rounded-lg hover:opacity-60 transition" id="accept-btn-${req.id}">
				Accept
				</button>
				<button class="bg-red-600 text-white px-3 py-1 rounded-lg hover:opacity-60 transition" id="reject-btn-${req.id}">
				Reject
				</button>
				</div>
				`;

				requestsContainer.appendChild(card);

				const acceptBtn = card.querySelector(`#accept-btn-${req.id}`) as HTMLButtonElement;
				const rejectBtn = card.querySelector(`#reject-btn-${req.id}`) as HTMLButtonElement;

				console.log("Request card created for request ID:", req.id, "with accept btn:", acceptBtn);

				if (acceptBtn) {
					acceptBtn.addEventListener("click", async () => {
						console.log("Accept button clicked for request:", req.id);
						await handleRequest(req.id, 'accept', card);
					});
				}

				if (rejectBtn) {
					rejectBtn.addEventListener("click", async () => {
						console.log("Reject button clicked for request:", req.id);
						await handleRequest(req.id, 'reject', card);
					});
				}
			});

		}
		catch (err) {
			console.error("Load requests error:", err);
			emptyMessage.textContent = "Error loading requests.";
		}
	}

	async function handleRequest(requestId: number, action: 'accept' | 'reject', cardElement: HTMLElement) {
		try {
			const endpoint = action === 'accept' ? '/friend-accept' : '/friend-reject';

			const res = await fetch(endpoint, {
				method: "POST",
				headers: {
					"Content-Type": "application/json"
				},
				credentials: "include",
				body: JSON.stringify({ request_id: requestId })
			});

			const data = await res.json();

			if (!res.ok) {
				alert(data.message || `Error ${action}ing request`);
				return;
			}

			cardElement.remove();
			alert(`Request ${action}ed successfully`);

		}
		catch (err) {
			console.error(`${action} request error:`, err);
			alert(`Error ${action}ing request`);
		}
	}
});
