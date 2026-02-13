class EmoteChanged {
    constructor(data) {
        this.op = data.op;
        this.d = data.d;
    }
}

async function getOriginsForSetID(setID) {
    var info = await getEmoteSetsData(Chat.info.channelID)
    for (var i = 0; i < info.emote_sets.length; i++) {
        if (info.emote_sets[i].id === setID) {
            return info.emote_sets[i].origins
        }
    }
    return []
}

function subscribeToOrigins(origins, conn) {
    console.log("Subscribing to new origins")
    // subscribe to emote events for the origins
    if (origins.length > 0) {
        for (var i = 0; i < origins.length; i++) {
            conn.send(JSON.stringify({
                op: 35, // subscribe opcode
                d: {
                    type: "emote_set.*", // subscription type
                    condition: {
                        object_id: origins[i].id // origin ID
                    }
                }
            }));
        }
    }
}

function unsubscribeFromOrigins(origins, conn) {
    console.log("unubscribing from old origins")
    // unsubscribe from emote events for the origins
    if (origins.length > 0) {
        for (var i = 0; i < origins.length; i++) {
            conn.send(JSON.stringify({
                op: 36, // unsubscribe opcode
                d: {
                    type: "emote_set.*", // subscription type
                    condition: {
                        object_id: origins[i].id // origin ID
                    }
                }
            }));
        }
    }
}

function seven_ws(channel) {
    (async () => {
        var info = await getUserInfo(Chat.info.channelID);
        var origins = await getOriginsForSetID(info.emoteSetID)
        var id = info.id;
        var emoteSetID = info.emoteSetID;
        var currentEmoteSetID = emoteSetID
        if (id === null || emoteSetID === null) {
            return
        }

        const options = {
            debug: true,
            reconnectInterval: 3000,
            maxReconnectInterval: 30000,
        };

        const conn = new ReconnectingWebSocket('wss://events.7tv.io/v3', [], options);

        conn.onopen = function () {
            console.log(`[${channel}] Successfully connected to websocket!`);

            // Subscribe to emote set events for the channel
            conn.send(JSON.stringify({
                op: 35, // subscribe opcode
                d: {
                    type: "emote_set.*", // subscription type
                    condition: {
                        object_id: emoteSetID // Emote set ID
                    }
                }
            }));
            // Subscribe to user events for the channel
            conn.send(JSON.stringify({
                op: 35, // subscribe opcode
                d: {
                    type: "user.*", // subscription type
                    condition: {
                        object_id: id // channel ID
                    }
                }
            }));

            console.log("Subscribing to origins")
            // subscribe to emote events for the origins
            if (origins.length > 0) {
                for (var i = 0; i < origins.length; i++) {
                    conn.send(JSON.stringify({
                        op: 35, // subscribe opcode
                        d: {
                            type: "emote_set.*", // subscription type
                            condition: {
                                object_id: origins[i].id // origin ID
                            }
                        }
                    }));
                }
            }
        };

        conn.onmessage = function (event) {
            try {
                const msg = JSON.parse(event.data);
                const emoteEvent = new EmoteChanged(msg);

                if (msg.op === 1) {
                    console.log(`[${channel}] Connection info received | HB Interval: ${emoteEvent.d.heartbeat_interval} | Session ID: ${emoteEvent.d.session_id} | Subscription Limit: ${emoteEvent.d.subscription_limit}`);
                } else if (msg.op === 2) {
                    // heartbeat
                } else if (msg.op === 6 || emoteEvent.op === 7) {
                    console.log(`[${channel}] Error occurred, reconnecting...`);
                    conn.refresh();
                } else if (msg.op === 4) {
                    console.log(`[${channel}] The server requested a reconnect, reconnecting...`);
                    conn.refresh();
                } else if (msg.op === 5) {
                    var type = msg.d.data.type
                    var command = msg.d.command
                    if (command === "SUBSCRIBE") {
                        console.log(`[${channel}] Successfully subscribed to ${type}`)
                    } else if (command === "UNSUBSCRIBE") {
                        console.log(`[${channel}] Successfully unsubscribed from ${type}`)
                    } else {
                        console.log(`[${channel}] Unknown confirmation command: ${command}`)
                    }
                } else if (msg.op === 0) {
                    if (msg.d.type === "emote_set.update") {
                        if (emoteEvent.d && emoteEvent.d.body) {
                            if (emoteEvent.d.body.pushed && emoteEvent.d.body.pushed.length > 0) {
                                console.log(`[${channel}] Added: ${emoteEvent.d.body.pushed[0].value.name}`);
                                SendInfoText(`Added: ${emoteEvent.d.body.pushed[0].value.name}`);
                                const emoteData = emoteEvent.d.body.pushed[0].value.data.host.files.pop();
                                var link = `https:${emoteEvent.d.body.pushed[0].value.data.host.url}/${emoteData.name}`;
                                // if link ends in .gif replace with .webp
                                if (link.endsWith(".gif")) link = link.replace(".gif", ".webp")
                                Chat.info.emotes[emoteEvent.d.body.pushed[0].value.name] = {
                                    id: emoteEvent.d.body.pushed[0].value.id,
                                    image: link,
                                    zeroWidth: emoteEvent.d.body.pushed[0].value.data.flags == 256,
                                };
                            } else if (emoteEvent.d.body.pulled && emoteEvent.d.body.pulled.length > 0) {
                                console.log(`[${channel}] Removed: ${emoteEvent.d.body.pulled[0].old_value.name}`);
                                SendInfoText(`Removed: ${emoteEvent.d.body.pulled[0].old_value.name}`);
                                delete Chat.info.emotes[emoteEvent.d.body.pulled[0].old_value.name];
                            } else if (emoteEvent.d.body.updated && emoteEvent.d.body.updated.length > 0) {
                                if (emoteEvent.d.body.updated[0].key == "origins") {
                                    var origin = 0; // blank id for now
                                    for (var i = 0; i < emoteEvent.d.body.updated.length; i++) { // loop through all updated values
                                        if (emoteEvent.d.body.updated[i].old_value.length > 0) { // removed emote origin
                                            for (var j = 0; j < emoteEvent.d.body.updated[i].old_value.length; j++) { // loop through all removed origins
                                                origin = emoteEvent.d.body.updated[i].old_value[j].id
                                                // Unsubscribe from emote set events for the old origin
                                                conn.send(JSON.stringify({
                                                    op: 36, // unsubscribe opcode
                                                    d: {
                                                        type: "emote_set.*", // subscription type
                                                        condition: {
                                                            object_id: origin // Emote set ID
                                                        }
                                                    }
                                                }));
                                            }
                                        }

                                        if (emoteEvent.d.body.updated[i].value.length > 0) { // added emote origin
                                            for (var j = 0; j < emoteEvent.d.body.updated[i].value.length; j++) { // loop through all added origins
                                                origin = emoteEvent.d.body.updated[i].value[j].id;
                                                // Subscribe to emote set events for the new origin
                                                conn.send(JSON.stringify({
                                                    op: 35, // subscribe opcode
                                                    d: {
                                                        type: "emote_set.*", // subscription type
                                                        condition: {
                                                            object_id: origin // Emote set ID
                                                        }
                                                    }
                                                }));
                                            }
                                        }
                                    }
                                    Chat.loadEmotes(Chat.info.channelID);
                                    SendInfoText("Emote origin changed")
                                    console.log("Cyan Chat: Emote origin changed, refreshing emotes...");
                                    return
                                }

                                console.log(`[${channel}] Renamed: ${emoteEvent.d.body.updated[0].old_value.name} to ${emoteEvent.d.body.updated[0].value.name}`);
                                SendInfoText(`Renamed: ${emoteEvent.d.body.updated[0].old_value.name} to ${emoteEvent.d.body.updated[0].value.name}`);
                                delete Chat.info.emotes[emoteEvent.d.body.updated[0].old_value.name];
                                const emoteData = emoteEvent.d.body.updated[0].value.data.host.files.pop();
                                var link = `https:${emoteEvent.d.body.updated[0].value.data.host.url}/${emoteData.name}`;
                                // if link ends in .gif replace with .webp
                                if (link.endsWith(".gif")) link = link.replace(".gif", ".webp")
                                Chat.info.emotes[emoteEvent.d.body.updated[0].value.name] = {
                                    id: emoteEvent.d.body.updated[0].value.id,
                                    image: `https:${emoteEvent.d.body.updated[0].value.data.host.url}/${emoteData.name}`,
                                    zeroWidth: emoteEvent.d.body.updated[0].value.data.flags == 256,
                                };
                            } else {
                                console.log(`Unknown event: ${event.data}`);
                            }
                        }
                    } else if (msg.d.type === "user.update") {
                        Chat.loadEmotes(Chat.info.channelID);
                        var oldEmoteSetName = msg.d.body.updated[0].value[0].old_value.name
                        var newEmoteSetName = msg.d.body.updated[0].value[0].value.name
                        var newEmoteSetID = msg.d.body.updated[0].value[0].value.id
                        var actor = msg.d.body.actor.display_name
                        SendInfoText(`${actor} changed the Emote Set to "${newEmoteSetName}"`)
                        // Unsubscribe from the current emote set events for the channel
                        conn.send(JSON.stringify({
                            op: 36, // unsubscribe opcode
                            d: {
                                type: "emote_set.*", // subscription type
                                condition: {
                                    object_id: currentEmoteSetID // Emote set ID
                                }
                            }
                        }));
                        console.log("unubscribing from old origins")
                        // unsubscribe from emote events for the origins
                        if (origins.length > 0) {
                            for (var i = 0; i < origins.length; i++) {
                                conn.send(JSON.stringify({
                                    op: 36, // unsubscribe opcode
                                    d: {
                                        type: "emote_set.*", // subscription type
                                        condition: {
                                            object_id: origins[i].id // origin ID
                                        }
                                    }
                                }));
                            }
                        }
                        // Subscribe to emote set events for the channel
                        conn.send(JSON.stringify({
                            op: 35, // subscribe opcode
                            d: {
                                type: "emote_set.*", // subscription type
                                condition: {
                                    object_id: newEmoteSetID // Emote set ID
                                }
                            }
                        }));
                        currentEmoteSetID = newEmoteSetID;
                        getOriginsForSetID(newEmoteSetID).then(newOrigins => {
                            console.log(newOrigins);
                            console.log("Subscribing to new origins");
                            // subscribe to emote events for the origins
                            if (newOrigins.length > 0) {
                                for (var i = 0; i < newOrigins.length; i++) {
                                    conn.send(JSON.stringify({
                                        op: 35, // subscribe opcode
                                        d: {
                                            type: "emote_set.*", // subscription type
                                            condition: {
                                                object_id: newOrigins[i].id // origin ID
                                            }
                                        }
                                    }));
                                }
                            }
                        });
                    } else {
                        console.log(`Unknown event: ${event.data}`);
                    }
                }
            } catch (error) {
                console.error(`Error processing message: ${error}`);
            }
        };

        conn.onclose = function (event) {
            console.log(`[${channel}] WebSocket closed. Reason: ${event.reason}`);
        };

        conn.onerror = function (error) {
            console.error(`[${channel}] WebSocket error: ${error}`);
        };
    })();
}

// Usage example:
// const channelId = 'your_channel_id';
// const channelName = 'your_channel_name';
// ws(channelId, channelName);

// ============================================================
// Shared Chat 7TV WebSocket Functions
// ============================================================

// Track shared chat 7TV WS connections for cleanup
var sharedSevenWSConnections = {};

function seven_ws_shared(channelName, channelID) {
    console.log(`[TEMP DEBUG][SharedChat][7TV] Starting 7TV WS for shared channel ${channelName} (${channelID})`); // TEMPORARY DEBUG
    (async () => {
        try {
            var info = await getUserInfo(channelID);
            if (!info || info.id === null || info.emoteSetID === null) {
                console.log(`[TEMP DEBUG][SharedChat][7TV] No 7TV info for ${channelName}, skipping WS`); // TEMPORARY DEBUG
                return;
            }

            var emoteSetID = info.emoteSetID;

            const options = {
                debug: false,
                reconnectInterval: 3000,
                maxReconnectInterval: 30000,
            };

            const conn = new ReconnectingWebSocket('wss://events.7tv.io/v3', [], options);

            // Store the connection for cleanup
            sharedSevenWSConnections[channelID] = conn;
            if (Chat.info.sharedChatChannels[channelID]) {
                Chat.info.sharedChatChannels[channelID].sevenConn = conn;
            }

            conn.onopen = function () {
                console.log(`[TEMP DEBUG][SharedChat][7TV] Connected to WS for ${channelName}`); // TEMPORARY DEBUG

                // Subscribe to emote set events for the shared channel
                conn.send(JSON.stringify({
                    op: 35, // subscribe opcode
                    d: {
                        type: "emote_set.*",
                        condition: {
                            object_id: emoteSetID
                        }
                    }
                }));
            };

            conn.onmessage = function (event) {
                try {
                    const msg = JSON.parse(event.data);

                    // Skip non-dispatch messages
                    if (msg.op !== 0) return;

                    const channelData = Chat.info.sharedChatChannels[channelID];
                    if (!channelData) {
                        // Channel was cleaned up, close connection
                        console.log(`[TEMP DEBUG][SharedChat][7TV] Channel ${channelName} data gone, closing WS`); // TEMPORARY DEBUG
                        conn.close();
                        return;
                    }

                    if (msg.d.type === "emote_set.update") {
                        const emoteEvent = new EmoteChanged(msg);
                        if (emoteEvent.d && emoteEvent.d.body) {
                            if (emoteEvent.d.body.pushed && emoteEvent.d.body.pushed.length > 0) {
                                const pushed = emoteEvent.d.body.pushed[0];
                                const emoteData = pushed.value.data.host.files.pop();
                                var link = `https:${pushed.value.data.host.url}/${emoteData.name}`;
                                if (link.endsWith(".gif")) link = link.replace(".gif", ".webp");
                                channelData.emotes[pushed.value.name] = {
                                    id: pushed.value.id,
                                    image: link,
                                    zeroWidth: pushed.value.data.flags == 256,
                                };
                                console.log(`[TEMP DEBUG][SharedChat][7TV] Added emote in ${channelName}: ${pushed.value.name}`); // TEMPORARY DEBUG
                            } else if (emoteEvent.d.body.pulled && emoteEvent.d.body.pulled.length > 0) {
                                const pulled = emoteEvent.d.body.pulled[0];
                                delete channelData.emotes[pulled.old_value.name];
                                console.log(`[TEMP DEBUG][SharedChat][7TV] Removed emote in ${channelName}: ${pulled.old_value.name}`); // TEMPORARY DEBUG
                            } else if (emoteEvent.d.body.updated && emoteEvent.d.body.updated.length > 0) {
                                const updated = emoteEvent.d.body.updated[0];
                                if (updated.key !== "origins") {
                                    // Rename
                                    delete channelData.emotes[updated.old_value.name];
                                    const emoteData = updated.value.data.host.files.pop();
                                    var link = `https:${updated.value.data.host.url}/${emoteData.name}`;
                                    if (link.endsWith(".gif")) link = link.replace(".gif", ".webp");
                                    channelData.emotes[updated.value.name] = {
                                        id: updated.value.id,
                                        image: link,
                                        zeroWidth: updated.value.data.flags == 256,
                                    };
                                    console.log(`[TEMP DEBUG][SharedChat][7TV] Renamed emote in ${channelName}: ${updated.old_value.name} -> ${updated.value.name}`); // TEMPORARY DEBUG
                                }
                            }
                        }
                    }
                } catch (error) {
                    console.error(`[TEMP DEBUG][SharedChat][7TV] Error processing message for ${channelName}: ${error}`); // TEMPORARY DEBUG
                }
            };

            conn.onclose = function (event) {
                console.log(`[TEMP DEBUG][SharedChat][7TV] WS closed for ${channelName}. Reason: ${event.reason}`); // TEMPORARY DEBUG
            };

            conn.onerror = function (error) {
                console.error(`[TEMP DEBUG][SharedChat][7TV] WS error for ${channelName}: ${error}`); // TEMPORARY DEBUG
            };
        } catch (error) {
            console.error(`[TEMP DEBUG][SharedChat][7TV] Failed to start WS for ${channelName}: ${error}`); // TEMPORARY DEBUG
        }
    })();
}

function seven_ws_shared_close(channelID) {
    console.log(`[TEMP DEBUG][SharedChat][7TV] Closing WS for channel ${channelID}`); // TEMPORARY DEBUG
    const conn = sharedSevenWSConnections[channelID];
    if (conn) {
        conn.close();
        delete sharedSevenWSConnections[channelID];
    }
}
