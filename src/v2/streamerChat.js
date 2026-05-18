/**
 * streamerChat.js — Streamer Chat Mode for Cyan Chat
 *
 * Activated when ?streamer_chat=true is in the URL.
 * Handles Twitch PKCE auth, message sending, moderation buttons,
 * slash command autocomplete, and poll/prediction modals.
 */

var StreamerChat = (function () {
    "use strict";

    // ============================================================
    // Constants
    // ============================================================

    var TWITCH_OAUTH_SCOPES = [
        "user:write:chat",
        "moderator:manage:chat_messages",
        "moderator:manage:banned_users",
        "moderator:manage:announcements",
        "moderator:manage:chat_settings",
        "channel:manage:polls",
        "channel:manage:predictions",
        "channel:manage:moderators",
        "channel:manage:vips",
        "channel:manage:raids",
        "channel:manage:broadcast",
        "channel:edit:commercial",
        "user:manage:chat_color",
        "user:read:moderated_channels",
    ].join(" ");

    var CLIENT_ID = ""; // populated from server token response

    var SLASH_COMMANDS = [
        { cmd: "/ban", desc: "Ban a user" },
        { cmd: "/unban", desc: "Unban a user" },
        { cmd: "/timeout", desc: "Timeout a user (seconds)" },
        { cmd: "/untimeout", desc: "Remove timeout from a user" },
        { cmd: "/delete", desc: "Delete a message by ID" },
        { cmd: "/clear", desc: "Clear chat" },
        { cmd: "/slow", desc: "Enable slow mode" },
        { cmd: "/slowoff", desc: "Disable slow mode" },
        { cmd: "/subscribers", "desc": "Enable subscribers-only mode" },
        { cmd: "/subscribersoff", desc: "Disable subscribers-only mode" },
        { cmd: "/emoteonly", desc: "Enable emote-only mode" },
        { cmd: "/emoteonlyoff", desc: "Disable emote-only mode" },
        { cmd: "/poll", desc: "Create a Twitch Poll" },
        { cmd: "/prediction", desc: "Create a Twitch Prediction" },
        { cmd: "/announce", desc: "Announce in primary (purple)" },
        { cmd: "/announceblue", desc: "Announce in blue" },
        { cmd: "/announcegreen", desc: "Announce in green" },
        { cmd: "/announceorange", desc: "Announce in orange" },
        { cmd: "/announcepurple", desc: "Announce in purple" },
        { cmd: "/w", desc: "Whisper a user (deprecated)" },
        { cmd: "/color", desc: "Change your chat color" },
        { cmd: "/me", desc: "Send an action message" },
        { cmd: "/raid", desc: "Raid a channel" },
        { cmd: "/unraid", desc: "Cancel a raid" },
        { cmd: "/commercial", desc: "Start an ad" },
        { cmd: "/marker", desc: "Add a stream marker" },
        { cmd: "/mod", desc: "Make a user a mod" },
        { cmd: "/unmod", desc: "Remove a user's mod status" },
        { cmd: "/vip", desc: "Give a user VIP status" },
        { cmd: "/unvip", desc: "Remove a user's VIP status" },
    ];

    var DEFAULT_MOD_ACTIONS = [
        { type: "delete", label: "Del", duration: 0 },
        { type: "timeout", label: "10m", duration: 600 },
        { type: "ban", label: "Ban", duration: 0 },
    ];

    var LS_TOKEN = "cyan_streamer_token";
    var LS_REFRESH = "cyan_streamer_refresh";
    var LS_EXPIRY = "cyan_streamer_expiry";
    var LS_MOD_ACTIONS = "cyan_mod_actions";
    var LS_KEEP_DELETED = "cyan_streamer_keep_deleted";
    var SS_VERIFIER = "cyan_pkce_verifier";
    var SS_REDIRECT_URI = "cyan_pkce_redirect";
    var SS_RETURN_URL = "cyan_pkce_return_url";

    var _autocompleteIndex = -1;

    // Emote autocomplete state
    var _emoteACMode = false;
    var _emoteACMatches = [];
    var _emoteACPage = 0;
    var _emoteACPageSize = 6;
    var _emoteACIndex = 0;
    var _emoteACTriggerStart = 0;

    // Scroll-to-bottom tracking (streamer mode)
    var _atBottom = true;
    var _scrollObserver = null;

    // ============================================================
    // Utility helpers
    // ============================================================

    function showError(msg, context) {
        console.error("[StreamerChat]", context || "", msg);
        var $err = $("#streamer_auth_error");
        $err.text(msg).show();
        setTimeout(function () { $err.hide(); }, 6000);
    }

    function apiCall(method, path, body, userToken) {
        var opts = {
            method: method,
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + (userToken || localStorage.getItem(LS_TOKEN) || ""),
            },
        };
        if (body != null) opts.body = JSON.stringify(body);
        return fetch(path, opts).then(function (r) {
            if (!r.ok) {
                return r.text().then(function (t) { throw new Error(r.status + ": " + t); });
            }
            // 204 No Content (e.g. Twitch DELETE endpoints) — no body to parse.
            if (r.status === 204) return null;
            var ct = r.headers.get("Content-Type") || "";
            if (ct.includes("application/json")) return r.json();
            return r.text();
        });
    }

    // ============================================================
    // PKCE helpers
    // ============================================================

    function generateCodeVerifier() {
        var arr = new Uint8Array(32);
        crypto.getRandomValues(arr);
        return btoa(String.fromCharCode.apply(null, arr))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    function generateCodeChallenge(verifier) {
        var data = new TextEncoder().encode(verifier);
        return crypto.subtle.digest("SHA-256", data).then(function (hash) {
            return btoa(String.fromCharCode.apply(null, new Uint8Array(hash)))
                .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
        });
    }

    // ============================================================
    // Auth
    // ============================================================

    function buildRedirectUri() {
        // Normalize: strip trailing index.html so the URI is consistent regardless
        // of whether the page is accessed as /v2/ or /v2/index.html.
        var path = window.location.pathname.replace(/\/index\.html$/, "/");
        if (!path.endsWith("/")) path += "/";
        return window.location.origin + path;
    }

    function init() {
        if (!Chat.info.streamerChat) return;
        if (!Chat.info.preview) $("#streamer_auth_bar").show();
        applyDisplaySettings(loadDisplaySettings());
        if (!Chat.info.preview) { initAuth(); bindUI(); }
    }

    function initAuth() {
        var token = localStorage.getItem(LS_TOKEN);
        if (!token) {
            showLoginButton();
            return;
        }
        validateAndInit(token);
    }

    function showLoginButton() {
        $("#streamer_login_btn").show();
        $("#streamer_user_info").hide();
    }

    function startLogin() {
        var verifier = generateCodeVerifier();
        var redirectUri = buildRedirectUri();
        // Store both for callback — the exact same URI must be sent on exchange.
        sessionStorage.setItem(SS_VERIFIER, verifier);
        sessionStorage.setItem(SS_REDIRECT_URI, redirectUri);
        // Save the full current URL so we can return to it (with channel params) after auth.
        sessionStorage.setItem(SS_RETURN_URL, window.location.href);
        console.log("[StreamerChat] Register this Redirect URL in your Twitch app:", redirectUri);
        generateCodeChallenge(verifier).then(function (challenge) {
            var params = new URLSearchParams({
                response_type: "code",
                client_id: "",
                redirect_uri: redirectUri,
                scope: TWITCH_OAUTH_SCOPES,
                state: "streamer_login",
                code_challenge: challenge,
                code_challenge_method: "S256",
            });
            // We need the client ID from the server — fetch it first
            fetch("/api/streamer/client_id").then(function (r) {
                if (!r.ok) { showError("Could not fetch client ID from server"); return; }
                return r.json();
            }).then(function (data) {
                if (!data) return;
                var cid = data.client_id || data.clientId || "";
                params.set("client_id", cid);
                window.location.href = "https://id.twitch.tv/oauth2/authorize?" + params.toString();
            }).catch(function (e) { showError("Login failed: " + e.message, "startLogin"); });
        });
    }

    function handleCallback() {
        var params = new URLSearchParams(window.location.search);
        var code = params.get("code");
        var state = params.get("state");
        if (!code || state !== "streamer_login") return;

        var verifier = sessionStorage.getItem(SS_VERIFIER);
        if (!verifier) { showError("Missing PKCE verifier — please try logging in again."); return; }

        // Use the exact URI that was sent during startLogin — must match exactly.
        var redirectUri = sessionStorage.getItem(SS_REDIRECT_URI) || buildRedirectUri();
        apiCall("POST", "/api/streamer/token", { code: code, code_verifier: verifier, redirect_uri: redirectUri }, null)
            .then(function (data) {
                sessionStorage.removeItem(SS_VERIFIER);
                sessionStorage.removeItem(SS_REDIRECT_URI);
                localStorage.setItem(LS_TOKEN, data.access_token);
                localStorage.setItem(LS_REFRESH, data.refresh_token);
                var expiry = Date.now() + (data.expires_in || 14400) * 1000;
                localStorage.setItem(LS_EXPIRY, String(expiry));
                // Return to the original overlay URL that was open before the OAuth redirect.
                var returnUrl = sessionStorage.getItem(SS_RETURN_URL);
                sessionStorage.removeItem(SS_RETURN_URL);
                if (returnUrl) {
                    window.location.replace(returnUrl);
                } else {
                    // Fallback: just strip auth params from the current URL in-place.
                    var cleanUrl = window.location.pathname + (window.location.hash || "");
                    var keep = new URLSearchParams();
                    params.forEach(function (v, k) {
                        if (k !== "code" && k !== "state" && k !== "scope") keep.set(k, v);
                    });
                    var qs = keep.toString();
                    history.replaceState(null, "", cleanUrl + (qs ? "?" + qs : ""));
                    validateAndInit(data.access_token);
                }
            })
            .catch(function (e) { showError("Auth failed: " + e.message, "handleCallback"); });
    }

    function validateAndInit(token) {
        refreshIfNeeded().then(function () {
            var broadcasterID = Chat.info.channelID;
            if (!broadcasterID) {
                // channelID may not be loaded yet — wait briefly
                setTimeout(function () { validateAndInit(localStorage.getItem(LS_TOKEN)); }, 1500);
                return;
            }
            apiCall("GET", "/api/streamer/check-mod?broadcaster_id=" + encodeURIComponent(broadcasterID), null, token)
                .then(function (data) {
                    Chat.info.streamerIsMod = data.is_mod;
                    Chat.info.streamerUserId = data.user_id;
                    Chat.info.streamerLogin = data.login;
                    $("#streamer_login_btn").hide();
                    $("#streamer_username").text(data.display_name || data.login);
                    $("#streamer_user_info").show();
                    if (data.is_mod && !Chat.info.preview) {
                        $("#streamer_bar").show();
                    } else if (!data.is_mod) {
                        showError("You are not a mod or broadcaster for this channel.");
                    }
                })
                .catch(function (e) {
                    showError("Validation failed: " + e.message, "validateAndInit");
                    showLoginButton();
                });
        });
    }

    function refreshIfNeeded() {
        var expiry = parseInt(localStorage.getItem(LS_EXPIRY) || "0", 10);
        var oneHour = 3600 * 1000;
        if (expiry - Date.now() > oneHour) return Promise.resolve();
        var refresh = localStorage.getItem(LS_REFRESH);
        if (!refresh) return Promise.resolve();
        return apiCall("POST", "/api/streamer/refresh", { refresh_token: refresh }, null)
            .then(function (data) {
                localStorage.setItem(LS_TOKEN, data.access_token);
                if (data.refresh_token) localStorage.setItem(LS_REFRESH, data.refresh_token);
                var expiry = Date.now() + (data.expires_in || 14400) * 1000;
                localStorage.setItem(LS_EXPIRY, String(expiry));
            })
            .catch(function (e) {
                console.error("[StreamerChat] Token refresh failed:", e);
            });
    }

    // ============================================================
    // UI bindings
    // ============================================================

    function bindUI() {
        $("#streamer_login_btn").on("click", startLogin);

        // Send message on button click or Enter (not Shift+Enter)
        $("#chat_send_btn").on("click", sendMessage);
        $("#chat_input").on("keydown", function (e) {
            var val = $(this).val();
            // Arrow keys / Tab / Enter / Escape for autocomplete
            if ($("#command_autocomplete").is(":visible")) {
                var items = $("#command_autocomplete .autocomplete-item");
                if (e.key === "ArrowDown") {
                    e.preventDefault();
                    if (_emoteACMode) {
                        var maxRendered = Math.min((_emoteACPage + 1) * _emoteACPageSize, _emoteACMatches.length);
                        if (_emoteACIndex >= maxRendered - 1 && maxRendered < _emoteACMatches.length) {
                            _emoteACPage++;
                            _emoteACIndex++;
                            renderEmoteAutocomplete();
                        } else {
                            _emoteACIndex = Math.min(_emoteACIndex + 1, maxRendered - 1);
                            items.removeClass("selected").eq(_emoteACIndex).addClass("selected");
                        }
                    } else {
                        _autocompleteIndex = Math.min(_autocompleteIndex + 1, items.length - 1);
                        items.removeClass("selected").eq(_autocompleteIndex).addClass("selected");
                    }
                    return;
                }
                if (e.key === "ArrowUp") {
                    e.preventDefault();
                    if (_emoteACMode) {
                        _emoteACIndex = Math.max(_emoteACIndex - 1, 0);
                        items.removeClass("selected").eq(_emoteACIndex).addClass("selected");
                    } else {
                        _autocompleteIndex = Math.max(_autocompleteIndex - 1, 0);
                        items.removeClass("selected").eq(_autocompleteIndex).addClass("selected");
                    }
                    return;
                }
                if (e.key === "Tab") {
                    e.preventDefault();
                    var sel = items.filter(".selected");
                    if (sel.length) sel.trigger("click");
                    return;
                }
                if (e.key === "Enter") {
                    var sel = items.filter(".selected");
                    if (sel.length) {
                        e.preventDefault();
                        sel.trigger("click");
                        return;
                    }
                }
                if (e.key === "Escape") {
                    hideAutocomplete();
                    return;
                }
            } else if (e.key === "Tab" && !val.startsWith("/")) {
                // Tab-triggered emote autocomplete: match the word before the cursor
                var cursorPos = this.selectionStart;
                var beforeCursor = val.substring(0, cursorPos);
                var wordMatch = beforeCursor.match(/(\S+)$/);
                if (wordMatch && wordMatch[1].length >= 1) {
                    e.preventDefault();
                    showEmoteAutocomplete(wordMatch[1], cursorPos - wordMatch[1].length, cursorPos);
                }
                return;
            }
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        $("#chat_input").on("input", handleAutocompleteInput);

        $(document).on("click", function (e) {
            if (!$(e.target).closest("#command_autocomplete, #chat_input").length) {
                hideAutocomplete();
            }
        });

        // Delegated mod button handler — direct binding is lost when chat lines are
        // serialized to HTML strings and re-inserted into the DOM.
        $(document).on("click", ".mod-btn", function (e) {
            e.stopPropagation();
            var $btn = $(this);
            var $chatLine = $btn.closest(".chat_line");
            var action = {
                type: $btn.attr("data-mod-type"),
                duration: parseInt($btn.attr("data-mod-duration"), 10) || 0,
                label: $btn.text(),
            };
            var nick = $btn.attr("data-mod-nick");
            var msgId = $btn.attr("data-mod-msgid");
            var userId = $btn.attr("data-mod-userid");
            executeModAction(action, nick, msgId, userId, $chatLine);
        });

        // Settings gear — opens unified panel on Display tab
        $("#streamer_settings_btn").on("click", function () { openSettingsPanel("display"); });

        // Tab switching within the unified settings panel
        $(document).on("click", ".sc-tab[data-tab]", function () {
            var tab = $(this).data("tab");
            if (tab === "mod") {
                openModActionsSettings();
            } else {
                openSettingsPanel(tab);
            }
        });

        // Display settings — save, reset
        $("#ds_reset_btn").on("click", function () {
            populateDisplayForm(Object.assign({}, DEFAULT_DISPLAY));
        });
        $("#ds_save_btn").on("click", function () {
            var settings = readDisplayForm();
            saveDisplaySettings(settings);
            applyDisplaySettings(settings);
            $("#mod_settings_overlay").hide();
        });
        // Show/hide outline sub-options
        $("#ds_pi_mode").on("change", function () {
            if ($(this).val() === "outline") {
                $(".ds-pi-outline").show();
            } else {
                $(".ds-pi-outline").hide();
            }
        });
        // Show/hide custom font input
        $("#ds_font").on("change", function () {
            if ($(this).val() === "-1") {
                $("#ds_custom_font_row").show();
            } else {
                $("#ds_custom_font_row").hide();
            }
        });
        // Close unified modal button
        $("#mod_settings_close_btn").on("click", function () { $("#mod_settings_overlay").hide(); });
        $("#mod_settings_save_btn").on("click", saveModSettings);
        $("#mod_add_type").on("change", function () {
            var isTimeout = $(this).val() === "timeout";
            $("#mod_add_duration").toggle(isTimeout);
        });
        // Close unified settings modal on overlay background click
        $("#mod_settings_overlay").on("click", function (e) {
            if (e.target === this) $(this).hide();
        });
        $("#mod_add_btn").on("click", addModAction);

        // Poll modal
        $("#poll_cancel_btn").on("click", function () { $("#poll_modal").hide(); });
        $("#poll_add_choice").on("click", function () { addChoiceRow("#poll_choices", "Choice", 5, 25); });
        $("#poll_submit_btn").on("click", submitPoll);
        bindChoiceRemoveButtons("#poll_choices");

        // Prediction modal
        $("#prediction_cancel_btn").on("click", function () { $("#prediction_modal").hide(); });
        $("#prediction_add_outcome").on("click", function () { addChoiceRow("#prediction_outcomes", "Outcome", 10, 25); });
        $("#prediction_submit_btn").on("click", submitPrediction);
        bindChoiceRemoveButtons("#prediction_outcomes");

        // Scrollable chat: auto-scroll to bottom unless user has scrolled up
        var $cc = $("#chat_container");
        $cc.on("scroll", function () {
            var el = this;
            _atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
        });
        _scrollObserver = new MutationObserver(function () {
            if (_atBottom) {
                var el = $cc[0];
                el.scrollTop = el.scrollHeight;
            }
        });
        _scrollObserver.observe($cc[0], { childList: true });

        // Emote/badge tooltip
        var $tooltip = $('<div id="sc-tooltip"></div>').appendTo("body");
        $(document).on("mouseenter", "img.emote[data-name], img.badge[data-name]", function (e) {
            $tooltip.text($(this).attr("data-name")).show();
            positionTooltip(e);
        }).on("mouseleave", "img.emote, img.badge", function () {
            $tooltip.hide();
        }).on("mousemove", "img.emote[data-name], img.badge[data-name]", function (e) {
            positionTooltip(e);
        });

        function positionTooltip(e) {
            var x = e.clientX, y = e.clientY;
            var tw = $tooltip.outerWidth() || 0;
            var th = $tooltip.outerHeight() || 20;
            var left = Math.min(x + 12, window.innerWidth - tw - 8);
            var top = y - th - 8;
            if (top < 0) top = y + 16;
            $tooltip.css({ left: left, top: top });
        }
    }

    // ============================================================
    // Message sending
    // ============================================================

    // Resolve a Twitch login name to a numeric user ID via the server's app token.
    function getUserId(login) {
        return fetch("/twitch/get_id?username=" + encodeURIComponent(login))
            .then(function (r) {
                if (!r.ok) throw new Error("User not found: " + login);
                return r.json();
            }).then(function (data) {
                if (!data.data || !data.data[0]) throw new Error("User not found: " + login);
                return data.data[0].id;
            });
    }

    // Shared wrapper: refresh token, run apiFn, clear input, re-enable button.
    // Returns the promise so callers can chain .then() for post-success side effects.
    function executeSlashCommand(apiFn) {
        var $btn = $("#chat_send_btn");
        $btn.prop("disabled", true);
        var p = refreshIfNeeded().then(apiFn).then(function (res) {
            $("#chat_input").val("").focus();
            hideAutocomplete();
            return res;
        }).catch(function (e) {
            showError("Command failed: " + e.message, "executeSlashCommand");
        }).finally(function () {
            $btn.prop("disabled", false);
        });
        return p;
    }

    // Dispatch a slash command. Returns true if handled, false to fall through to chat.
    function handleSlashCommand(text) {
        var parts = text.slice(1).split(/\s+/);
        var cmd = parts[0].toLowerCase();
        var args = parts.slice(1);

        var broadcasterID = Chat.info.channelID;
        var moderatorID = Chat.info.streamerUserId;

        switch (cmd) {
            // These go through as plain chat messages.
            case "me":
            case "w":
                return false;

            case "announce":
            case "announceblue":
            case "announcegreen":
            case "announceorange":
            case "announcepurple": {
                if (!args.length) { showError("/" + cmd + " requires a message"); return true; }
                var announceColor = cmd === "announce" ? "primary" : cmd.replace("announce", "");
                executeSlashCommand(function () {
                    return apiCall("POST", "/api/streamer/announce", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        message: args.join(" "),
                        color: announceColor,
                    });
                });
                return true;
            }

            case "slow":
                executeSlashCommand(function () {
                    return apiCall("PATCH", "/api/streamer/chat-settings", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        slow_mode: true,
                        slow_mode_wait_time: parseInt(args[0]) || 30,
                    });
                });
                return true;

            case "slowoff":
                executeSlashCommand(function () {
                    return apiCall("PATCH", "/api/streamer/chat-settings", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        slow_mode: false,
                    });
                });
                return true;

            case "subscribers":
                executeSlashCommand(function () {
                    return apiCall("PATCH", "/api/streamer/chat-settings", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        subscriber_mode: true,
                    });
                });
                return true;

            case "subscribersoff":
                executeSlashCommand(function () {
                    return apiCall("PATCH", "/api/streamer/chat-settings", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        subscriber_mode: false,
                    });
                });
                return true;

            case "emoteonly":
                executeSlashCommand(function () {
                    return apiCall("PATCH", "/api/streamer/chat-settings", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        emote_mode: true,
                    });
                });
                return true;

            case "emoteonlyoff":
                executeSlashCommand(function () {
                    return apiCall("PATCH", "/api/streamer/chat-settings", {
                        broadcaster_id: broadcasterID,
                        moderator_id: moderatorID,
                        emote_mode: false,
                    });
                });
                return true;

            case "clear":
                executeSlashCommand(function () {
                    return apiCall("DELETE",
                        "/api/streamer/chat-clear?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                        "&moderator_id=" + encodeURIComponent(moderatorID), null);
                }).then(function () {
                    $(".chat_line").remove();
                });
                return true;

            case "delete":
                if (!args[0]) { showError("/delete requires a message ID"); return true; }
                executeSlashCommand(function () {
                    return apiCall("DELETE",
                        "/api/streamer/messages?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                        "&moderator_id=" + encodeURIComponent(moderatorID) +
                        "&message_id=" + encodeURIComponent(args[0]), null);
                });
                return true;

            case "ban":
                if (!args[0]) { showError("/ban requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("POST", "/api/streamer/bans", {
                            broadcaster_id: broadcasterID,
                            moderator_id: moderatorID,
                            user_id: userId,
                            duration: 0,
                            reason: args.slice(1).join(" "),
                        });
                    });
                });
                return true;

            case "timeout":
                if (!args[0]) { showError("/timeout requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("POST", "/api/streamer/bans", {
                            broadcaster_id: broadcasterID,
                            moderator_id: moderatorID,
                            user_id: userId,
                            duration: parseInt(args[1]) || 600,
                            reason: args.slice(2).join(" "),
                        });
                    });
                });
                return true;

            case "unban":
            case "untimeout":
                if (!args[0]) { showError("/" + cmd + " requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("DELETE",
                            "/api/streamer/bans?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                            "&moderator_id=" + encodeURIComponent(moderatorID) +
                            "&user_id=" + encodeURIComponent(userId), null);
                    });
                });
                return true;

            case "color":
                if (!args[0]) { showError("/color requires a color value"); return true; }
                executeSlashCommand(function () {
                    return apiCall("PUT", "/api/streamer/color", {
                        user_id: moderatorID,
                        color: args[0],
                    });
                });
                return true;

            case "commercial":
                executeSlashCommand(function () {
                    return apiCall("POST", "/api/streamer/commercial", {
                        broadcaster_id: broadcasterID,
                        length: parseInt(args[0]) || 30,
                    });
                });
                return true;

            case "marker":
                executeSlashCommand(function () {
                    return apiCall("POST", "/api/streamer/markers", {
                        user_id: broadcasterID,
                        description: args.join(" "),
                    });
                });
                return true;

            case "raid":
                if (!args[0]) { showError("/raid requires a channel name"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (targetId) {
                        return apiCall("POST", "/api/streamer/raids", {
                            from_broadcaster_id: broadcasterID,
                            to_broadcaster_id: targetId,
                        });
                    });
                });
                return true;

            case "unraid":
                executeSlashCommand(function () {
                    return apiCall("DELETE",
                        "/api/streamer/raids?broadcaster_id=" + encodeURIComponent(broadcasterID), null);
                });
                return true;

            case "mod":
                if (!args[0]) { showError("/mod requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("POST", "/api/streamer/mods", {
                            broadcaster_id: broadcasterID,
                            user_id: userId,
                        });
                    });
                });
                return true;

            case "unmod":
                if (!args[0]) { showError("/unmod requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("DELETE",
                            "/api/streamer/mods?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                            "&user_id=" + encodeURIComponent(userId), null);
                    });
                });
                return true;

            case "vip":
                if (!args[0]) { showError("/vip requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("POST", "/api/streamer/vips", {
                            broadcaster_id: broadcasterID,
                            user_id: userId,
                        });
                    });
                });
                return true;

            case "unvip":
                if (!args[0]) { showError("/unvip requires a username"); return true; }
                executeSlashCommand(function () {
                    return getUserId(args[0]).then(function (userId) {
                        return apiCall("DELETE",
                            "/api/streamer/vips?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                            "&user_id=" + encodeURIComponent(userId), null);
                    });
                });
                return true;

            default:
                return false;
        }
    }

    function sendMessage() {
        var text = $("#chat_input").val().trim();
        if (!text) return;

        // Slash command shortcuts (poll / prediction open modals)
        if (text === "/poll") { openPollModal(); return; }
        if (text === "/prediction") { openPredictionModal(); return; }

        // Dispatch all other slash commands.
        if (text.startsWith("/") && handleSlashCommand(text)) return;

        var broadcasterID = Chat.info.channelID;
        var senderID = Chat.info.streamerUserId;
        if (!broadcasterID || !senderID) {
            showError("Not authenticated or channel not loaded.");
            return;
        }

        var $btn = $("#chat_send_btn");
        $btn.prop("disabled", true);

        refreshIfNeeded().then(function () {
            return apiCall("POST", "/api/streamer/messages", {
                broadcaster_id: broadcasterID,
                sender_id: senderID,
                message: text,
            });
        }).then(function () {
            $("#chat_input").val("").focus();
            hideAutocomplete();
        }).catch(function (e) {
            showError("Send failed: " + e.message, "sendMessage");
        }).finally(function () {
            $btn.prop("disabled", false);
        });
    }

    // ============================================================
    // Moderation buttons
    // ============================================================

    function loadModActions() {
        try {
            var stored = localStorage.getItem(LS_MOD_ACTIONS);
            if (stored) return JSON.parse(stored);
        } catch (e) { /* fall through */ }
        return JSON.parse(JSON.stringify(DEFAULT_MOD_ACTIONS));
    }

    function saveModActions(actions) {
        localStorage.setItem(LS_MOD_ACTIONS, JSON.stringify(actions));
    }

    function renderModButtons($chatLine, nick, msgId, userId, service) {
        if (service === "youtube") return;
        if ($chatLine.find(".mod-actions").length) return; // already rendered
        var actions = loadModActions();
        var $wrap = $("<div class='mod-actions'></div>");
        actions.forEach(function (action) {
            var cssClass = "mod-btn mod-btn--" + action.type;
            // Store all needed data in attributes — click handlers are lost when
            // $chatLine is serialized to an HTML string before DOM insertion.
            // A delegated handler (bound in bindUI) reads these attributes instead.
            var $btn = $("<button></button>")
                .addClass(cssClass)
                .text(action.label)
                .attr("title", labelForAction(action))
                .attr("data-mod-type", action.type)
                .attr("data-mod-duration", action.duration || 0)
                .attr("data-mod-nick", nick)
                .attr("data-mod-msgid", msgId || "")
                .attr("data-mod-userid", userId || "");
            $wrap.append($btn);
        });
        $chatLine.append($wrap);
    }

    function labelForAction(action) {
        if (action.type === "timeout") return "Timeout " + action.duration + "s";
        if (action.type === "ban") return "Permanent ban";
        if (action.type === "unban") return "Unban";
        return "Delete message";
    }

    function executeModAction(action, nick, msgId, userId, $chatLine) {
        var broadcasterID = Chat.info.channelID;
        var moderatorID = Chat.info.streamerUserId;
        if (!broadcasterID || !moderatorID) return;

        refreshIfNeeded().then(function () {
            if (action.type === "delete") {
                return apiCall("DELETE",
                    "/api/streamer/messages?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                    "&moderator_id=" + encodeURIComponent(moderatorID) +
                    "&message_id=" + encodeURIComponent(msgId), null);
            }
            if (action.type === "ban" || action.type === "timeout") {
                return apiCall("POST", "/api/streamer/bans", {
                    broadcaster_id: broadcasterID,
                    moderator_id: moderatorID,
                    user_id: userId,
                    duration: action.type === "timeout" ? action.duration : 0,
                    reason: "",
                });
            }
            if (action.type === "unban") {
                return apiCall("DELETE",
                    "/api/streamer/bans?broadcaster_id=" + encodeURIComponent(broadcasterID) +
                    "&moderator_id=" + encodeURIComponent(moderatorID) +
                    "&user_id=" + encodeURIComponent(userId), null);
            }
        }).then(function () {
            var keepDeleted = localStorage.getItem(LS_KEEP_DELETED) === "true";
            if (keepDeleted) {
                var label = action.type === "timeout" ? "timed out" : action.type === "ban" ? "banned" : "deleted";
                if (action.type === "delete") {
                    markDeleted(msgId, label);
                } else {
                    markUserDeleted(nick, label);
                }
            } else {
                if (action.type === "delete") {
                    $(".chat_line[data-id=" + msgId + "]").remove();
                } else {
                    $(".chat_line[data-nick=" + nick + "]").remove();
                }
            }
        }).catch(function (e) {
            showError("Mod action failed: " + e.message, "executeModAction");
        });
    }

    // ============================================================
    // Deleted message marking
    // ============================================================

    function markDeleted(msgId, label) {
        $(".chat_line[data-id=" + msgId + "]")
            .addClass("chat_line--deleted")
            .attr("data-deleted-label", label || "deleted");
    }

    function markUserDeleted(nick, label) {
        $(".chat_line[data-nick=" + nick + "]")
            .addClass("chat_line--deleted")
            .attr("data-deleted-label", label || "timed out");
    }

    function markAllDeleted(label) {
        $(".chat_line")
            .addClass("chat_line--deleted")
            .attr("data-deleted-label", label || "cleared");
    }

    // ============================================================
    // Display settings
    // ============================================================

    var LS_DISPLAY = "cyan_display_settings";

    var DEFAULT_DISPLAY = {
        bodyBg: "#18181b",
        chatBg: "#242427",
        altBgEnabled: false,
        altBg: "#2a2a2e",
        font: 0,
        customFont: "",
        size: 2,
        height: 3,
        emoteScale: 1,
        platformIndicator: "none",
        piStyle: "solid",
        piSides: "left",
        piThickness: 3,
        piRadius: 0,
    };

    function loadDisplaySettings() {
        try {
            var saved = JSON.parse(localStorage.getItem(LS_DISPLAY));
            if (saved && typeof saved === "object") {
                return Object.assign({}, DEFAULT_DISPLAY, saved);
            }
        } catch (e) { /* ignore */ }
        // No localStorage — seed from URL params (Chat.info)
        var fromUrl = {};
        if (Chat.info) {
            fromUrl.size = Chat.info.size != null ? Chat.info.size : DEFAULT_DISPLAY.size;
            fromUrl.height = Chat.info.height != null ? Chat.info.height : DEFAULT_DISPLAY.height;
            if (typeof Chat.info.font === "number") {
                fromUrl.font = Chat.info.font;
            } else if (typeof Chat.info.font === "string" && Chat.info.font) {
                fromUrl.font = -1;
                fromUrl.customFont = Chat.info.font;
            }
            if (Chat.info.emoteScale) fromUrl.emoteScale = Chat.info.emoteScale;
            if (Chat.info.platformIndicator) fromUrl.platformIndicator = Chat.info.platformIndicator;
            if (Chat.info.piStyle) fromUrl.piStyle = Chat.info.piStyle;
            if (Chat.info.piSides) fromUrl.piSides = Chat.info.piSides;
            if (Chat.info.piThickness) fromUrl.piThickness = Chat.info.piThickness;
            if (Chat.info.piRadius != null) fromUrl.piRadius = Chat.info.piRadius;
        }
        return Object.assign({}, DEFAULT_DISPLAY, fromUrl);
    }

    function saveDisplaySettings(settings) {
        localStorage.setItem(LS_DISPLAY, JSON.stringify(settings));
    }

    function applyDisplaySettings(settings) {
        var root = document.documentElement;

        // Colors
        root.style.setProperty("--sc-body-bg", settings.bodyBg || DEFAULT_DISPLAY.bodyBg);
        root.style.setProperty("--sc-chat-bg", settings.chatBg || DEFAULT_DISPLAY.chatBg);
        root.style.setProperty("--sc-alt-bg", settings.altBgEnabled ? (settings.altBg || DEFAULT_DISPLAY.altBg) : "transparent");

        // Font
        var fontIdx = parseInt(settings.font);
        if (fontIdx === -1) {
            // Custom font from Google Fonts
            if (settings.customFont) {
                loadCustomFont(settings.customFont);
            }
        } else if (fontIdx >= 0 && fontIdx < fonts.length) {
            replaceCSS("font", fonts[fontIdx]);
        }

        // Size (0=tiny,1=small,2=medium,3=large)
        var sizeIdx = parseInt(settings.size);
        if (isNaN(sizeIdx)) sizeIdx = 2;
        var sizeName = sizes[sizeIdx];
        if (sizeName) replaceCSS("size", sizeName);
        var scaleMap = { 0: 1, 1: 20 / 14, 2: 34 / 14, 3: 48 / 14 };
        if (Chat.info) Chat.info.seven_scale = scaleMap[sizeIdx] !== undefined ? scaleMap[sizeIdx] : (34 / 14);

        // Height
        var heightIdx = parseInt(settings.height);
        if (!isNaN(heightIdx) && heights[heightIdx]) {
            replaceCSS("height", heights[heightIdx]);
        }

        // Emote scale
        removeEmoteScaleCSS();
        var emoteScaleVal = parseInt(settings.emoteScale) || 1;
        if (emoteScaleVal > 1 && sizeName) {
            appendCSS("emoteScale_" + sizeName, emoteScaleVal);
        }

        // Platform indicator
        applyPlatformIndicator(
            settings.platformIndicator || "none",
            settings.piSides || "left",
            settings.piStyle || "solid",
            settings.piThickness || 3,
            settings.piRadius || 0
        );
    }

    function populateDisplayForm(settings) {
        // Colors
        $("#ds_body_bg").val(settings.bodyBg || DEFAULT_DISPLAY.bodyBg);
        $("#ds_chat_bg").val(settings.chatBg || DEFAULT_DISPLAY.chatBg);
        $("#ds_alt_bg_enabled").prop("checked", !!settings.altBgEnabled);
        $("#ds_alt_bg").val(settings.altBg || DEFAULT_DISPLAY.altBg);

        // Typography
        var fontVal = settings.font != null ? settings.font : DEFAULT_DISPLAY.font;
        $("#ds_font").val(String(fontVal));
        if (fontVal === -1) {
            $("#ds_custom_font_row").show();
            $("#ds_custom_font").val(settings.customFont || "");
        } else {
            $("#ds_custom_font_row").hide();
        }
        $("#ds_size").val(String(settings.size != null ? settings.size : DEFAULT_DISPLAY.size));
        $("#ds_height").val(String(settings.height != null ? settings.height : DEFAULT_DISPLAY.height));

        // Emotes
        $("#ds_emote_scale").val(String(settings.emoteScale != null ? settings.emoteScale : DEFAULT_DISPLAY.emoteScale));

        // Platform indicator
        var piMode = settings.platformIndicator || "none";
        $("#ds_pi_mode").val(piMode);
        if (piMode === "outline") {
            $(".ds-pi-outline").show();
        } else {
            $(".ds-pi-outline").hide();
        }
        $("#ds_pi_style").val(settings.piStyle || DEFAULT_DISPLAY.piStyle);
        $("#ds_pi_sides").val(settings.piSides || DEFAULT_DISPLAY.piSides);
        $("#ds_pi_thickness").val(String(settings.piThickness != null ? settings.piThickness : DEFAULT_DISPLAY.piThickness));
        $("#ds_pi_radius").val(String(settings.piRadius != null ? settings.piRadius : DEFAULT_DISPLAY.piRadius));

        // Refresh Coloris so swatches reflect new values
        if (window.Coloris) {
            Coloris({ el: "#ds_body_bg, #ds_chat_bg, #ds_alt_bg", theme: "default", themeMode: "dark", alpha: false });
        }
    }

    function readDisplayForm() {
        var fontVal = parseInt($("#ds_font").val());
        if (isNaN(fontVal)) fontVal = 0;
        return {
            bodyBg: $("#ds_body_bg").val() || DEFAULT_DISPLAY.bodyBg,
            chatBg: $("#ds_chat_bg").val() || DEFAULT_DISPLAY.chatBg,
            altBgEnabled: $("#ds_alt_bg_enabled").is(":checked"),
            altBg: $("#ds_alt_bg").val() || DEFAULT_DISPLAY.altBg,
            font: fontVal,
            customFont: fontVal === -1 ? ($("#ds_custom_font").val().trim() || "") : "",
            size: parseInt($("#ds_size").val()),
            height: parseInt($("#ds_height").val()),
            emoteScale: parseInt($("#ds_emote_scale").val()) || 1,
            platformIndicator: $("#ds_pi_mode").val() || "none",
            piStyle: $("#ds_pi_style").val() || "solid",
            piSides: $("#ds_pi_sides").val() || "left",
            piThickness: parseInt($("#ds_pi_thickness").val()) || 3,
            piRadius: parseInt($("#ds_pi_radius").val()) || 0,
        };
    }

    function openSettingsPanel(tab) {
        tab = tab || "display";
        $(".sc-tab").removeClass("sc-tab--active");
        $(".sc-tab[data-tab='" + tab + "']").addClass("sc-tab--active");
        $("[id^='settings_tab_']").hide();
        $("#settings_tab_" + tab).show();
        if (tab === "display") {
            populateDisplayForm(loadDisplaySettings());
        } else if (tab === "mod") {
            openModActionsSettings();
            return; // openModActionsSettings already calls show()
        }
        $("#mod_settings_overlay").show();
    }

    function openDisplaySettings() {
        openSettingsPanel("display");
    }

    // ============================================================
    // Mod settings panel
    // ============================================================

    function openModActionsSettings() {
        var actions = loadModActions();
        var $list = $("#mod_actions_list").empty();
        actions.forEach(function (action, idx) {
            var $row = $("<div class='mod-action-row'></div>");
            var desc = action.type === "timeout"
                ? action.label + " (" + action.duration + "s timeout)"
                : action.label + " (" + action.type + ")";
            $row.append("<span class='row-label'>" + escapeHtml(desc) + "</span>");

            var $up = $("<button class='mod-row-btn' title='Move up'>&#8593;</button>").on("click", function () {
                if (idx === 0) return;
                actions.splice(idx - 1, 0, actions.splice(idx, 1)[0]);
                saveModActions(actions);
                openModActionsSettings();
            });
            var $down = $("<button class='mod-row-btn' title='Move down'>&#8595;</button>").on("click", function () {
                if (idx === actions.length - 1) return;
                actions.splice(idx + 1, 0, actions.splice(idx, 1)[0]);
                saveModActions(actions);
                openModActionsSettings();
            });
            var $del = $("<button class='mod-row-btn danger' title='Remove'>&#10005;</button>").on("click", function () {
                actions.splice(idx, 1);
                saveModActions(actions);
                openModActionsSettings();
            });
            $row.append($up, $down, $del);
            $list.append($row);
        });

        // Keep-deleted toggle state
        $("#keep_deleted_toggle").prop("checked", localStorage.getItem(LS_KEEP_DELETED) === "true");
        // Ensure mod tab is active within the unified panel
        $(".sc-tab").removeClass("sc-tab--active");
        $(".sc-tab[data-tab='mod']").addClass("sc-tab--active");
        $("[id^='settings_tab_']").hide();
        $("#settings_tab_mod").show();
        $("#mod_settings_overlay").show();
    }

    function addModAction() {
        var type = $("#mod_add_type").val();
        var label = $("#mod_add_label").val().trim();
        var duration = parseInt($("#mod_add_duration").val(), 10) || 0;
        if (!label) { alert("Please enter a button label."); return; }
        var actions = loadModActions();
        actions.push({ type: type, label: label, duration: duration });
        saveModActions(actions);
        $("#mod_add_label").val("");
        $("#mod_add_duration").val("");
        openModActionsSettings();
    }

    function saveModSettings() {
        var keepDeleted = $("#keep_deleted_toggle").is(":checked");
        localStorage.setItem(LS_KEEP_DELETED, keepDeleted ? "true" : "false");
        $("#mod_settings_overlay").hide();
    }

    // ============================================================
    // Slash command autocomplete
    // ============================================================

    function handleAutocompleteInput() {
        var val = $("#chat_input").val();
        if (val.startsWith("/")) {
            // Clear emote AC if switching to command mode
            if (_emoteACMode) { _emoteACMode = false; }

            var typedWord = val.split(" ")[0].toLowerCase();
            var matchedCommands = SLASH_COMMANDS.filter(function (c) {
                return c.cmd.startsWith(typedWord);
            });

            // If exactly one word and it matches a user-arg command, also offer recent chatters
            var afterSlash = val.slice(1);
            var parts = afterSlash.split(" ");
            var needsUser = ["/ban", "/unban", "/timeout", "/untimeout", "/mod", "/unmod", "/vip", "/unvip", "/raid"].includes(parts[0] ? "/" + parts[0] : "");
            var recentMatches = [];
            if (needsUser && parts.length >= 2) {
                var prefix = parts[parts.length - 1].toLowerCase();
                recentMatches = getRecentChatters(prefix).slice(0, 5);
                matchedCommands = [];
            }

            if (!matchedCommands.length && !recentMatches.length) { hideAutocomplete(); return; }

            var $ac = $("#command_autocomplete").empty().show();
            _autocompleteIndex = 0;

            matchedCommands.forEach(function (c) {
                var $item = $("<div class='autocomplete-item'></div>")
                    .append("<span class='autocomplete-cmd'>" + escapeHtml(c.cmd) + "</span>")
                    .append("<span class='autocomplete-desc'>" + escapeHtml(c.desc) + "</span>")
                    .on("click", function () {
                        var inputVal = c.cmd + " ";
                        if (c.cmd === "/poll") { openPollModal(); hideAutocomplete(); $("#chat_input").val("").focus(); return; }
                        if (c.cmd === "/prediction") { openPredictionModal(); hideAutocomplete(); $("#chat_input").val("").focus(); return; }
                        $("#chat_input").val(inputVal).focus();
                        hideAutocomplete();
                    });
                $ac.append($item);
            });

            recentMatches.forEach(function (nick) {
                var partsArr = val.split(" ");
                partsArr[partsArr.length - 1] = nick;
                var completed = partsArr.join(" ") + " ";
                var $item = $("<div class='autocomplete-item'></div>")
                    .append("<span class='autocomplete-cmd'>" + escapeHtml(nick) + "</span>")
                    .on("click", function () {
                        $("#chat_input").val(completed).focus();
                        hideAutocomplete();
                    });
                $ac.append($item);
            });

            // Auto-highlight the first item so Tab/Enter works immediately.
            $ac.children(".autocomplete-item").first().addClass("selected");
            return;
        }

        // Check for :word emote trigger before the cursor
        var input = document.getElementById("chat_input");
        var cursorPos = input.selectionStart;
        var beforeCursor = val.substring(0, cursorPos);
        var colonMatch = beforeCursor.match(/:(\w*)$/);
        if (colonMatch) {
            showEmoteAutocomplete(colonMatch[1], cursorPos - colonMatch[0].length, cursorPos);
            return;
        }

        hideAutocomplete();
    }

    function hideAutocomplete() {
        $("#command_autocomplete").hide().empty();
        _autocompleteIndex = -1;
        _emoteACMode = false;
        _emoteACMatches = [];
        _emoteACIndex = 0;
    }

    // ============================================================
    // Emote autocomplete
    // ============================================================

    function getEmoteList() {
        var seen = {};
        var result = [];
        // Channel emotes (BTTV, FFZ, 7TV)
        var emotes = Chat.info.emotes || {};
        Object.keys(emotes).forEach(function (name) {
            if (!seen[name]) {
                seen[name] = true;
                result.push({ name: name, image: emotes[name].image });
            }
        });
        // Personal 7TV emotes of the logged-in streamer
        var streamerUserId = Chat.info.streamerUserId;
        if (streamerUserId && Chat.info.seventvPersonalEmotes && Chat.info.seventvPersonalEmotes[streamerUserId]) {
            var personal = Chat.info.seventvPersonalEmotes[streamerUserId];
            Object.keys(personal).forEach(function (name) {
                if (!seen[name]) {
                    seen[name] = true;
                    result.push({ name: name, image: personal[name].image });
                }
            });
        }
        return result;
    }

    function showEmoteAutocomplete(prefix, triggerStart, cursorEnd) {
        var allEmotes = getEmoteList();
        var lc = prefix.toLowerCase();
        _emoteACMatches = allEmotes.filter(function (e) {
            return e.name.toLowerCase().includes(lc);
        }).sort(function (a, b) {
            var aStarts = a.name.toLowerCase().startsWith(lc);
            var bStarts = b.name.toLowerCase().startsWith(lc);
            if (aStarts && !bStarts) return -1;
            if (!aStarts && bStarts) return 1;
            return a.name.localeCompare(b.name);
        });
        _emoteACTriggerStart = triggerStart;
        _emoteACPage = 0;
        _emoteACIndex = 0;
        _emoteACMode = true;
        renderEmoteAutocomplete();
    }

    function renderEmoteAutocomplete() {
        var $ac = $("#command_autocomplete").empty();
        var slice = _emoteACMatches.slice(0, (_emoteACPage + 1) * _emoteACPageSize);
        if (slice.length === 0) { hideAutocomplete(); return; }
        slice.forEach(function (emote, i) {
            var $item = $("<div class='autocomplete-item emote-ac-item'></div>");
            if (i === _emoteACIndex) $item.addClass("selected");
            $item.append('<img class="autocomplete-emote-img" src="' + emote.image + '" alt="">');
            $item.append('<span class="autocomplete-cmd">' + escapeHtml(emote.name) + '</span>');
            (function (name) {
                $item.on("click", function () { insertEmote(name); });
            })(emote.name);
            $ac.append($item);
        });
        $ac.show();
    }

    function insertEmote(name) {
        var input = document.getElementById("chat_input");
        var val = input.value;
        var cursorPos = input.selectionStart;
        var before = val.substring(0, _emoteACTriggerStart);
        var after = val.substring(cursorPos);
        input.value = before + name + " " + after;
        var newCursor = _emoteACTriggerStart + name.length + 1;
        input.setSelectionRange(newCursor, newCursor);
        hideAutocomplete();
        $(input).focus();
    }

    function getRecentChatters(prefix) {
        var rc = Chat.info.recentChatters || {};
        return Object.keys(rc)
            .filter(function (n) { return !prefix || n.startsWith(prefix); })
            .sort(function (a, b) { return rc[b] - rc[a]; });
    }

    // ============================================================
    // Poll modal
    // ============================================================

    function openPollModal() {
        $("#poll_feedback").hide().removeClass("success error").text("");
        $("#poll_modal").show();
    }

    function addChoiceRow(listSelector, placeholder, maxRows, maxLen) {
        var $list = $(listSelector);
        if ($list.children().length >= maxRows) return;
        var idx = $list.children().length + 1;
        var $row = $("<div class='sc-choice-row'></div>")
            .append("<input type='text' placeholder='" + placeholder + " " + idx + "' maxlength='" + maxLen + "' />")
            .append("<button class='sc-remove-btn' title='Remove'>&#10005;</button>");
        $row.find(".sc-remove-btn").on("click", function () { $row.remove(); });
        $list.append($row);
    }

    function bindChoiceRemoveButtons(listSelector) {
        $(listSelector).on("click", ".sc-remove-btn", function () {
            var $list = $(listSelector);
            if ($list.children().length <= 2) return; // must keep at least 2
            $(this).closest(".sc-choice-row").remove();
        });
    }

    function submitPoll() {
        var title = $("#poll_title").val().trim();
        var duration = parseInt($("#poll_duration").val(), 10) || 60;
        var choices = [];
        $("#poll_choices input").each(function () {
            var v = $(this).val().trim();
            if (v) choices.push(v);
        });
        if (!title) { showFeedback("#poll_feedback", "Please enter a poll title.", false); return; }
        if (choices.length < 2) { showFeedback("#poll_feedback", "Please enter at least 2 choices.", false); return; }

        $("#poll_submit_btn").prop("disabled", true);
        refreshIfNeeded().then(function () {
            return apiCall("POST", "/api/streamer/polls", {
                broadcaster_id: Chat.info.channelID,
                title: title,
                choices: choices,
                duration: duration,
            });
        }).then(function () {
            showFeedback("#poll_feedback", "Poll started!", true);
            setTimeout(function () { $("#poll_modal").hide(); }, 1500);
        }).catch(function (e) {
            showFeedback("#poll_feedback", "Failed: " + e.message, false);
        }).finally(function () {
            $("#poll_submit_btn").prop("disabled", false);
        });
    }

    // ============================================================
    // Prediction modal
    // ============================================================

    function openPredictionModal() {
        $("#prediction_feedback").hide().removeClass("success error").text("");
        $("#prediction_modal").show();
    }

    function submitPrediction() {
        var title = $("#prediction_title").val().trim();
        var window_ = parseInt($("#prediction_window").val(), 10) || 120;
        var outcomes = [];
        $("#prediction_outcomes input").each(function () {
            var v = $(this).val().trim();
            if (v) outcomes.push(v);
        });
        if (!title) { showFeedback("#prediction_feedback", "Please enter a prediction title.", false); return; }
        if (outcomes.length < 2) { showFeedback("#prediction_feedback", "Please enter at least 2 outcomes.", false); return; }

        $("#prediction_submit_btn").prop("disabled", true);
        refreshIfNeeded().then(function () {
            return apiCall("POST", "/api/streamer/predictions", {
                broadcaster_id: Chat.info.channelID,
                title: title,
                outcomes: outcomes,
                prediction_window: window_,
            });
        }).then(function () {
            showFeedback("#prediction_feedback", "Prediction started!", true);
            setTimeout(function () { $("#prediction_modal").hide(); }, 1500);
        }).catch(function (e) {
            showFeedback("#prediction_feedback", "Failed: " + e.message, false);
        }).finally(function () {
            $("#prediction_submit_btn").prop("disabled", false);
        });
    }

    // ============================================================
    // Shared helpers
    // ============================================================

    function showFeedback(selector, msg, success) {
        $(selector)
            .removeClass("success error")
            .addClass(success ? "success" : "error")
            .text(msg)
            .show();
    }

    // ============================================================
    // Public API
    // ============================================================

    // Run handleCallback unconditionally on every page load.
    // This is needed because Twitch redirects to /v2/ (without ?streamer_chat=true),
    // so init() never runs there — but we still need to exchange the code.
    $(document).ready(function () { handleCallback(); });

    return {
        init: init,
        renderModButtons: renderModButtons,
        markDeleted: markDeleted,
        markUserDeleted: markUserDeleted,
        markAllDeleted: markAllDeleted,
    };
})();
