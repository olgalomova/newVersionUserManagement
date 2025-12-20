document.addEventListener("DOMContentLoaded", () => {
	const input = document.getElementById("searchInput") as HTMLInputElement;
	const btn = document.getElementById("searchBtn") as HTMLButtonElement;
	const resultsSection = document.getElementById("resultsSection") as HTMLElement;
	const resultsList = document.getElementById("resultsList") as HTMLElement;
	const message = document.getElementById("searchMessage") as HTMLElement;

	btn.addEventListener("click", async () => {
		const query = input.value.trim();
		message.textContent = "";

		if (!query) {
			message.textContent = "Enter a username to search.";
			resultsSection.classList.add("hidden");
			return;
		}

		try {
			const res = await fetch(`/search?query=${encodeURIComponent(query)}`, {
				credentials: "include"
			});

			const data = await res.json();
			resultsList.innerHTML = "";

			if (!res.ok) {
				message.textContent = data.message || "Search error";
				resultsSection.classList.add("hidden");
				return;
			}

			if (data.users.length === 0) {
				message.textContent = "No users found.";
				resultsSection.classList.add("hidden");
				return;
			}

			resultsSection.classList.remove("hidden");

			data.users.forEach((u: any) => {
				const card = document.createElement("div");
				card.className = "flex items-center justify-between p-3 bg-gray-100 rounded-xl";
				card.innerHTML = `
				<div class="flex items-center gap-3">
				<img src="/uploads/${u.avatar ? u.avatar : 'default.png'}"
				class="w-12 h-12 rounded-full object-cover">
				<div>
				<p class="font-semibold">${u.login}</p>
				<p class="text-gray-500 text-sm">${u.email}</p>
				</div>
				</div>
				<button class="add-friend-btn bg-blue-600 text-white px-3 py-1 rounded-lg hover:opacity-60 transition" data-user-id="${u.id}">
				Add
				</button>
				`;

				resultsList.appendChild(card);
				const addBtn = card.querySelector('.add-friend-btn') as HTMLButtonElement;

				if (addBtn) {
					addBtn.addEventListener("click", async () => {
						console.log("Clicked Add for user:", u.id);
						await sendFriendRequest(u.id, addBtn);
					});
				}
			});

		}
		catch (err) {
			console.error("Search error:", err);
			message.textContent = "Error performing search.";
		}
	});

	async function sendFriendRequest(addresseeId: number, btn: HTMLButtonElement) {
		try {
			btn.disabled = true;
			btn.textContent = "Sending...";

			const res = await fetch("/friend-request", {
				method: "POST",
				headers: {
					"Content-Type": "application/json"
				},
				credentials: "include",
				body: JSON.stringify({ addressee_id: addresseeId })
			});

			const data = await res.json();

			if (!res.ok) {
				alert(data.message || "Error sending friend request");
				btn.disabled = false;
				btn.textContent = "Add";
				return;
			}

			btn.disabled = true;
			btn.textContent = "Request Sent";
			btn.classList.remove("bg-blue-600");
			btn.classList.add("bg-gray-400");

		}
		catch (err) {
			console.error("Friend request error:", err);
			alert("Error sending friend request");
			btn.disabled = false;
			btn.textContent = "Add";
		}
	}
});
