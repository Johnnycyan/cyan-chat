if (Chat.info.yt) {
	// Determine the WebSocket protocol (ws:// or wss://) based on the current page protocol
	const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';

	// Construct the WebSocket URL using the current host, a relative path, and the channel parameter
	const wsUrl = `${wsProtocol}//${window.location.host}/ws?channel=${encodeURIComponent(Chat.info.yt)}`;

	// Create the WebSocket connection
	var yt_socket = new ReconnectingWebSocket(wsUrl, null, { reconnectInterval: 5000 });

	yt_socket.onopen = function () {
		console.log('YouTube: Connected');
		yt_socket.reconnectInterval = 5000;
	};

	yt_socket.onclose = function (event) {
		if (event.reason === 'Could not find stream by channel identifier') {
			console.log('YouTube: Channel not live, retrying in 60s');
			yt_socket.reconnectInterval = 60000;
		} else {
			console.log('YouTube: Disconnected: ', event.reason);
		}
	};

	function formatMessage(message) {
		let badges = ""
		let badge_info = true

		if (message.author.moderator == true) {
			badges += "youtubemod/1"
		}

		if (message.author.badges && message.author.badges.length > 0) {
			const authorName = message.author.name.replace("@", "").toLowerCase().trim();
			if (!Chat.info.userBadges[authorName]) {
				Chat.info.userBadges[authorName] = [];
			}

			message.author.badges.forEach(badge => {
				if (badge && badge.url) {
					const userBadge = {
						description: badge.tooltip || "YouTube Member",
						url: badge.url
					};
					// avoid duplicates
					if (!Chat.info.userBadges[authorName].some(b => b.url === userBadge.url)) {
						Chat.info.userBadges[authorName].push(userBadge);
					}
				}
			});
		}

		let info = {
			"badge-info": badge_info,
			"badges": badges,
			"color": true,
			"display-name": message.author.name.replace("@", ""),
			"emotes": true,
			"first-msg": "0",
			"flags": true,
			"id": message.id.replace(/\./g, ""),
			"mod": message.author.moderator ? 1 : 0,
			"returning-chatter": "0",
			"room-id": "133875470",
			"subscriber": "0",
			"tmi-sent-ts": message.unix,
			"turbo": "0",
			"user-id": message.author.id,
			"user-type": true,
			"runs": message.runs
		}

		return info
	}

	yt_socket.onmessage = function (data) {
		data = JSON.parse(data.data)
		if (data.info == "deleted") {
			Chat.clearMessage(String(data.message).replace(/\./g, ""))
		}
		else if (data.info == "banned") {
			setTimeout(function () {
				$('.chat_line[data-user-id="' + data.externalChannelId + '"]').remove();
			}, 200);
		}
		else if (data.type === "superchat") {
			let info = formatMessage(data)
			let msg = data.hasMessage ? `${data.purchase_amount} ${data.message}` : data.purchase_amount
			Chat.write(data.author.name.replace("@", "").toLowerCase().trim(), info, msg, "youtube")
		}
		else {
			let info = formatMessage(data)
			Chat.write(data.author.name.replace("@", "").toLowerCase().trim(), info, data.message, "youtube")
		}
	}
}