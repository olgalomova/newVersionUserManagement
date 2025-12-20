document.addEventListener("DOMContentLoaded", () => {
	const friendsList = document.getElementById("friendsList") as HTMLElement;
	const message = document.getElementById("friendsMessage") as HTMLElement;
	loadFriends();
	async function loadFriends() {
		try {
			message.textContent = "Loading...";
			const res = await fetch("/friends", {
				credentials: "include"
			});
			const data = await res.json();
			if (!res.ok) {
				message.textContent = data.message || "Error loading friends";
				return;
			}
			if (data.friends.length === 0) {
				message.textContent = "You have no friends yet.";
				friendsList.innerHTML = "";
				return;
			}
			message.textContent = "";
			friendsList.innerHTML = "";
			data.friends.forEach((friend: any) => {
				const card = document.createElement("div");
				card.className = "flex items-center justify-between p-4 bg-gray-100 rounded-xl mb-3";

				const isOnline = friend.onlineStatus === "online";
				const statusColor = isOnline ? "bg-green-500" : "bg-gray-400";
				const statusText = isOnline ? "Online" : "Offline";

				card.innerHTML = `
				<div class="flex items-center gap-3">
				<div class="relative">
				<img src="/uploads/${friend.avatar ? friend.avatar : 'default.png'}"
				class="w-12 h-12 rounded-full object-cover">
				<div class="${statusColor} w-3 h-3 rounded-full absolute bottom-0 right-0 border-2 border-white" title="${statusText}"></div>
				</div>
				<div>
				<p class="font-semibold">${friend.login}</p>
				<p class="text-gray-500 text-sm">${friend.email}</p>
				<p class="text-xs ${isOnline ? 'text-green-600' : 'text-gray-500'} font-medium">${statusText}</p>
				</div>
				</div>
				<button class="bg-red-600 text-white px-3 py-1 rounded-lg hover:opacity-60 transition" id="remove-btn-${friend.id}">
				Remove
				</button>
				`;
				friendsList.appendChild(card);
				const removeBtn = card.querySelector(`#remove-btn-${friend.id}`) as HTMLButtonElement;
				if (removeBtn) {
					removeBtn.addEventListener("click", async () => {
						console.log("Remove friend:", friend.id);
						await removeFriend(friend.id, card);
					});
				}
			});
		}
		catch (err) {
			console.error("Load friends error:", err);
			message.textContent = "Error loading friends.";
		}
	}
	async function removeFriend(friendId: number, cardElement: HTMLElement) {
		try {
			const res = await fetch("/friend-remove", {
				method: "DELETE",
				headers: {
					"Content-Type": "application/json"
				},
				credentials: "include",
				body: JSON.stringify({ friend_id: friendId })
			});
			const data = await res.json();
			if (!res.ok) {
				alert(data.message || "Error removing friend");
				return;
			}
			cardElement.remove();
			alert("Friend removed");
		}
		catch (err) {
			console.error("Remove friend error:", err);
			alert("Error removing friend");
		}
	}
});
