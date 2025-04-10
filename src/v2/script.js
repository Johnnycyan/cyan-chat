(function ($) {
  // Thanks to BrunoLM (https://stackoverflow.com/a/3855394)
  $.QueryString = (function (paramsArray) {
    let params = {};

    for (let i = 0; i < paramsArray.length; ++i) {
      let param = paramsArray[i].split("=", 2);

      if (param.length !== 2) continue;

      params[param[0]] = decodeURIComponent(param[1].replace(/\+/g, " "));
    }

    return params;
  })(window.location.search.substr(1).split("&"));

  // // Check if 'v' parameter exists
  // if (!$.QueryString.hasOwnProperty("v")) {
  //   console.log("'v' parameter is not present.");
  //   var currentUrl = window.location.href;
  //   var newUrl = addRandomQueryString(currentUrl);
  //   window.location.href = newUrl;
  // } else {
  //   // Check if 'v' parameter is valid
  //   if (Date.now() - $.QueryString.v > 10000) {
  //     console.log("'v' parameter is not up to date.");
  //     var currentUrl = window.location.href;
  //     var cleanUrl = removeRandomQueryString(currentUrl);
  //     var newUrl = addRandomQueryString(cleanUrl);
  //     window.location.href = newUrl;
  //   }
  // }
})(jQuery);

Chat = {
  info: {
    channel: null,
    connected: false,
    animate:
      "animate" in $.QueryString
        ? $.QueryString.animate.toLowerCase() === "true"
        : false,
    center:
      "center" in $.QueryString
        ? $.QueryString.center.toLowerCase() === "true"
        : false,
    sms:
      "sms" in $.QueryString
        ? $.QueryString.sms.toLowerCase() === "true"
        : false,
    showBots:
      "bots" in $.QueryString
        ? $.QueryString.bots.toLowerCase() === "true"
        : false,
    hideCommands:
      "hide_commands" in $.QueryString
        ? $.QueryString.hide_commands.toLowerCase() === "true"
        : false,
    hideBadges:
      "hide_badges" in $.QueryString
        ? $.QueryString.hide_badges.toLowerCase() === "true"
        : false,
    hidePaints:
      "hide_paints" in $.QueryString
        ? $.QueryString.hide_paints.toLowerCase() === "true"
        : false,
    hideColon:
      "hide_colon" in $.QueryString
        ? $.QueryString.hide_colon.toLowerCase() === "true"
        : false,
    // fade: ('fade' in $.QueryString ? parseInt($.QueryString.fade) : false),
    fade: "fade" in $.QueryString ? parseInt($.QueryString.fade) : 360,
    size: "size" in $.QueryString ? parseInt($.QueryString.size) : 2,
    height: "height" in $.QueryString ? parseInt($.QueryString.height) : 3,
    weight: "weight" in $.QueryString ? parseInt($.QueryString.weight) : 4,
    font:
      "font" in $.QueryString && !isNaN($.QueryString.font)
        ? parseInt($.QueryString.font)
        : $.QueryString.font || 0,
    stroke: "stroke" in $.QueryString ? parseInt($.QueryString.stroke) : false,
    shadow: "shadow" in $.QueryString ? parseInt($.QueryString.shadow) : 0,
    smallCaps:
      "small_caps" in $.QueryString
        ? $.QueryString.small_caps.toLowerCase() === "true"
        : false,
    invert:
      "invert" in $.QueryString
        ? $.QueryString.invert.toLowerCase() === "true"
        : false,
    emotes: {},
    badges: {},
    userBadges: {},
    specialBadges: {},
    ffzapBadges: null,
    bttvBadges: null,
    seventvBadges: [],
    seventvPaints: {},
    seventvCheckers: {},
    seventvPersonalEmotes: {},
    seventvNoUsers: {},
    seventvNonSubs: {},
    colors: {},
    chatterinoBadges: null,
    cheers: {},
    lines: [],
    blockedUsers:
      "block" in $.QueryString
        ? $.QueryString.block.toLowerCase().split(",")
        : false,
    bots: ["streamelements", "streamlabs", "nightbot", "moobot", "fossabot"],
    nicknameColor: "cN" in $.QueryString ? $.QueryString.cN : false,
    regex:
      "regex" in $.QueryString
        ? new RegExp(decodeURIComponent($.QueryString.regex))
        : null,
    emoteScale:
      "emoteScale" in $.QueryString ? parseInt($.QueryString.emoteScale) : 1,
    readable:
      "readable" in $.QueryString
        ? $.QueryString.readable.toLowerCase() === "true"
        : false,
    disableSync:
      "disable_sync" in $.QueryString
        ? $.QueryString.disable_sync.toLowerCase() === "true"
        : false,
    disablePruning:
      "disable_pruning" in $.QueryString
        ? $.QueryString.disable_pruning.toLowerCase() === "true"
        : false,
    yt:
      "yt" in $.QueryString
        ? $.QueryString.yt.toLowerCase().replace("@", "")
        : false,
    voice:
      "voice" in $.QueryString
        ? $.QueryString.voice.toLowerCase()
        : false,
    bigSoloEmotes:
      "big_emotes" in $.QueryString
        ? $.QueryString.big_emotes.toLowerCase() === "true"
        : false,
    messageImage:
      "img" in $.QueryString
        ? $.QueryString.img
        : false,
    disabledCommands:
      "off_commands" in $.QueryString
        ? $.QueryString.off_commands.toLowerCase().split(",")
        : [],
  },

  loadEmotes: function (channelID) {
    Chat.info.emotes = {};
    // Load BTTV, FFZ and 7TV emotes
    ["emotes/global", "users/twitch/" + encodeURIComponent(channelID)].forEach(
      (endpoint) => {
        $.getJSON(
          addRandomQueryString(
            "https://api.betterttv.net/3/cached/frankerfacez/" + endpoint
          )
        ).done(function (res) {
          res.forEach((emote) => {
            if (emote.images["4x"]) {
              var imageUrl = emote.images["4x"];
              var upscale = false;
            } else {
              var imageUrl = emote.images["2x"] || emote.images["1x"];
              var upscale = true;
            }
            Chat.info.emotes[emote.code] = {
              id: emote.id,
              image: imageUrl,
              upscale: upscale,
            };
          });
        });
      }
    );

    ["emotes/global", "users/twitch/" + encodeURIComponent(channelID)].forEach(
      (endpoint) => {
        $.getJSON(
          addRandomQueryString("https://api.betterttv.net/3/cached/" + endpoint)
        ).done(function (res) {
          if (!Array.isArray(res)) {
            res = res.channelEmotes.concat(res.sharedEmotes);
          }
          res.forEach((emote) => {
            Chat.info.emotes[emote.code] = {
              id: emote.id,
              image: "https://cdn.betterttv.net/emote/" + emote.id + "/3x",
              zeroWidth: [
                "5e76d338d6581c3724c0f0b2",
                "5e76d399d6581c3724c0f0b8",
                "567b5b520e984428652809b6",
                "5849c9a4f52be01a7ee5f79d",
                "567b5c080e984428652809ba",
                "567b5dc00e984428652809bd",
                "58487cc6f52be01a7ee5f205",
                "5849c9c8f52be01a7ee5f79e",
              ].includes(emote.id),
              // "5e76d338d6581c3724c0f0b2" => cvHazmat, "5e76d399d6581c3724c0f0b8" => cvMask, "567b5b520e984428652809b6" => SoSnowy, "5849c9a4f52be01a7ee5f79d" => IceCold, "567b5c080e984428652809ba" => CandyCane, "567b5dc00e984428652809bd" => ReinDeer, "58487cc6f52be01a7ee5f205" => SantaHat, "5849c9c8f52be01a7ee5f79e" => TopHat
            };
          });
        });
      }
    );

    $.getJSON(addRandomQueryString("https://7tv.io/v3/emote-sets/global")).done(
      (res) => {
        res?.emotes?.forEach((emote) => {
          const emoteData = emote.data.host.files.pop();
          var link = `https:${emote.data.host.url}/${emoteData.name}`;
          // if link ends in .gif replace with .webp
          if (link.endsWith(".gif")) link = link.replace(".gif", ".webp")
          Chat.info.emotes[emote.name] = {
            id: emote.id,
            image: link,
            zeroWidth: emote.data.flags == 256,
          };
        });
      }
    );

    $.getJSON(
      addRandomQueryString(
        "https://7tv.io/v3/users/twitch/" + encodeURIComponent(channelID)
      )
    ).done((res) => {
      res?.emote_set?.emotes?.forEach((emote) => {
        const emoteData = emote.data.host.files.pop();
        var link = `https:${emote.data.host.url}/${emoteData.name}`;
        // if link ends in .gif replace with .webp
        if (link.endsWith(".gif")) link = link.replace(".gif", ".webp")
        Chat.info.emotes[emote.name] = {
          id: emote.id,
          image: link,
          zeroWidth: emote.data.flags == 256,
        };
      });
    });
  },

  loadPersonalEmotes: async function (channelID) {
    var subbed = await isUserSubbed(channelID);
    if (!subbed) {
      return;
    }
    const emoteSetIDs = [];
    // var nnysNum = 0;

    try {
      const userResponse = await getPersonalEmoteData(channelID);

      userResponse?.emote_sets?.forEach((emoteSet) => {
        if (emoteSet.flags === 4 || emoteSet.flags === 11) {
          if (!emoteSetIDs.includes(emoteSet.id)) {
            emoteSetIDs.push(emoteSet.id);
          }
        }
      });

      Chat.info.seventvPersonalEmotes[channelID] = {};

      for (let i = 0; i < emoteSetIDs.length; i++) {
        const emoteSetResponse = await $.getJSON(
          addRandomQueryString(
            "https://7tv.io/v3/emote-sets/" + encodeURIComponent(emoteSetIDs[i])
          )
        );

        emoteSetResponse?.emotes?.forEach((emote) => {
          const emoteData = emote.data.host.files.pop();
          var link = `https:${emote.data.host.url}/${emoteData.name}`;
          // if link ends in .gif replace with .webp
          if (link.endsWith(".gif")) link = link.replace(".gif", ".webp")
          const personalEmote = {
            name: emote.name,
            id: emote.id,
            image: link,
            zeroWidth: emote.data.flags == 256,
          };
          // Add personalEmote if not already in Chat.info.seventvPersonalEmotes[channelID]
          if (!Chat.info.seventvPersonalEmotes[channelID][personalEmote.name]) {
            Chat.info.seventvPersonalEmotes[channelID][personalEmote.name] =
              personalEmote;
          }
        });
      }
    } catch (error) {
      // console.error("Error loading personal emotes: ", error);
    }
  },

  load: function (callback) {
    GetTwitchUserID(Chat.info.channel).done(function (res) {
      // console.log(res.data[0].id);
      Chat.info.channelID = res.data[0].id;
      Chat.loadEmotes(Chat.info.channelID);
      seven_ws(Chat.info.channel);

      client_id = res.client_id;

      // Load channel colors
      TwitchAPI("/chat/color?user_id=" + Chat.info.channelID).done(
        function (res) {
          res = res.data[0];
          Chat.info.colors[Chat.info.channel] = Chat.getUserColor(Chat.info.channel, res);
        }
      );
      Chat.loadUserPaints(Chat.info.channel, Chat.info.channelID);

      // Load CSS
      let size = sizes[Chat.info.size - 1];
      var font;
      if (typeof Chat.info.font === "number") {
        font = fonts[Chat.info.font];
        appendCSS("font", font);
      } else {
        loadCustomFont(Chat.info.font);
      }

      let emoteScale = 1;
      if (Chat.info.emoteScale > 1) {
        emoteScale = Chat.info.emoteScale;
      }
      if (emoteScale > 3) {
        emoteScale = 3;
      }

      if (Chat.info.center) {
        Chat.info.animate = false;
        Chat.info.invert = false;
        Chat.info.sms = false;
        appendCSS("variant", "center");
      } 
      
      if (Chat.info.sms) {
        Chat.info.center = false;
        Chat.info.animate = false;
        Chat.info.invert = false;
        Chat.info.shadow = 0;
        Chat.info.stroke = false;
        Chat.info.hidePaints = true;
        Chat.info.disablePruning = true;
        Chat.info.hideColon = false;
        appendCSS("variant", "sms");
      }

      appendCSS("size", size);
      if (emoteScale > 1) {
        appendCSS("emoteScale_" + size, emoteScale);
      }

      if (Chat.info.height) {
        if (Chat.info.height > 4) Chat.info.height = 4
        let height = heights[Chat.info.height];
        appendCSS("height", height);
      }
      if (Chat.info.stroke && Chat.info.stroke > 0) {
        if (Chat.info.stroke > 2) Chat.info.stroke = 2
        let stroke = strokes[Chat.info.stroke - 1];
        appendCSS("stroke", stroke);
      }
      if (Chat.info.weight) {
        console.log("Weight is "+Chat.info.weight)
        if (Chat.info.weight > 5 && Chat.info.weight < 100) {
          Chat.info.weight = 5;
          let weight = weights[Chat.info.weight - 1];
          appendCSS("weight", weight);
        } else if (Chat.info.weight >= 100) {
            $("#chat_container").css("font-weight", Chat.info.weight);
        } else {
          let weight = weights[Chat.info.weight - 1];
          appendCSS("weight", weight);
        }
      }
      if (Chat.info.shadow && Chat.info.shadow > 0) {
        if (Chat.info.shadow > 3) Chat.info.shadow = 3
        let shadow = shadows[Chat.info.shadow - 1];
        appendCSS("shadow", shadow);
      }
      if (Chat.info.smallCaps) {
        appendCSS("variant", "SmallCaps");
      }
      if (Chat.info.invert) {
        appendCSS("variant", "invert");
      }

      // Load badges
      TwitchAPI("/chat/badges/global").done(function (res) {
        res?.data.forEach((badge) => {
          badge?.versions.forEach((version) => {
            Chat.info.badges[badge.set_id + ":" + version.id] =
              version.image_url_4x;
          });
        });

        TwitchAPI("/chat/badges?broadcaster_id=" + Chat.info.channelID).done(
          function (res) {
            res?.data.forEach((badge) => {
              badge?.versions.forEach((version) => {
                Chat.info.badges[badge.set_id + ":" + version.id] =
                  version.image_url_4x;
              });
            });

            // const badgeUrl =
            //   "https://cdn.frankerfacez.com/room-badge/mod/" +
            //   Chat.info.channel +
            //   "/4/rounded";
            // const fallbackBadgeUrl =
            //   "https://static-cdn.jtvnw.net/badges/v1/3267646d-33f0-4b17-b3df-f923a41db1d0/3";

            $.getJSON(
              "https://api.frankerfacez.com/v1/_room/id/" +
              encodeURIComponent(Chat.info.channelID)
            ).done(function (res) {
              const badgeUrl =
                "https://cdn.frankerfacez.com/room-badge/mod/" +
                res.room.id +
                "/4/rounded";
              const fallbackBadgeUrl =
                "https://static-cdn.jtvnw.net/badges/v1/3267646d-33f0-4b17-b3df-f923a41db1d0/3";
              if (res.room.moderator_badge) {
                fetch(badgeUrl)
                  .then((response) => {
                    if (response.status === 404) {
                      Chat.info.badges["moderator:1"] = fallbackBadgeUrl;
                    } else {
                      Chat.info.badges["moderator:1"] = badgeUrl;
                    }
                  })
                  .catch((error) => {
                    console.error("Error fetching the badge URL:", error);
                    Chat.info.badges["moderator:1"] = fallbackBadgeUrl;
                  });
              }
              if (res.room.vip_badge) {
                Chat.info.badges["vip:1"] =
                  "https://cdn.frankerfacez.com/room-badge/vip/" +
                  res.room.id +
                  "/4";
              }
            });
          }
        );
      });

      if (!Chat.info.hideBadges) {
        $.getJSON("https://api.ffzap.com/v1/supporters")
          .done(function (res) {
            Chat.info.ffzapBadges = res;
          })
          .fail(function () {
            Chat.info.ffzapBadges = [];
          });
        $.getJSON("https://api.betterttv.net/3/cached/badges")
          .done(function (res) {
            Chat.info.bttvBadges = res;
          })
          .fail(function () {
            Chat.info.bttvBadges = [];
          });

        /* Deprecated endpoint
                $.getJSON('https://7tv.io/v3/badges?user_identifier=login')
                    .done(function(res) {
                        Chat.info.seventvBadges = res.badges;
                    })
                    .fail(function() {
                        Chat.info.seventvBadges = [];
                    });
                */

        $.getJSON("/api/chatterino-badges")
          .done(function (res) {
            Chat.info.chatterinoBadges = res.badges;
          })
          .fail(function () {
            Chat.info.chatterinoBadges = [];
          });

      }

      // Load cheers images
      TwitchAPI("/bits/cheermotes?broadcaster_id=" + Chat.info.channelID).done(
        function (res) {
          res = res.data;
          res.forEach((action) => {
            Chat.info.cheers[action.prefix] = {};
            action.tiers.forEach((tier) => {
              Chat.info.cheers[action.prefix][tier.min_bits] = {
                image: tier.images.dark.animated["4"],
                color: tier.color,
              };
            });
          });
        }
      );

      callback(true);
    });
  },

  update: setInterval(function () {
    if (Chat.info.lines.length > 0) {
      var lines = Chat.info.lines.join("");

      if (Chat.info.animate) {
        var $auxDiv = $("<div></div>", { class: "hidden" }).appendTo(
          "#chat_container"
        );
        $auxDiv.append(lines);
        var auxHeight = $auxDiv.height();
        $auxDiv.remove();

        var $animDiv = $("<div></div>");
        if (Chat.info.invert) {
          $("#chat_container").prepend($animDiv);
          $animDiv.animate({ height: auxHeight }, 150, function () {
            $(this).remove();
            $("#chat_container").prepend(lines);
          });
        } else {
          $("#chat_container").append($animDiv);
          $animDiv.animate({ height: auxHeight }, 150, function () {
            $(this).remove();
            $("#chat_container").append(lines);
          });
        }
      } else {
        if (Chat.info.invert) {
          $("#chat_container").prepend(lines);
        } else {
          $("#chat_container").append(lines);
        }
      }
      // if (Chat.info.invert) {
      //   $("#chat_container").prepend(lines);
      // } else {
      //   $("#chat_container").append(lines);
      // }
      Chat.info.lines = [];
      var linesToDelete = $(".chat_line").length - 100;
      if (Chat.info.invert) {
        while (linesToDelete > 0) {
          $(".chat_line").eq(-1).remove();
          linesToDelete--;
        }
      } else {
        while (linesToDelete > 0) {
          $(".chat_line").eq(0).remove();
          linesToDelete--;
        }
      }
    } else if (Chat.info.fade) {
      if (Chat.info.invert) {
        var messageTime = $(".chat_line").eq(-1).data("time");
        if ((Date.now() - messageTime) / 1000 >= Chat.info.fade) {
          $(".chat_line")
            .eq(-1)
            .fadeOut(function () {
              $(this).remove();
            });
        }
      } else {
        var messageTime = $(".chat_line").eq(0).data("time");
        if ((Date.now() - messageTime) / 1000 >= Chat.info.fade) {
          if (Chat.info.sms) {
            // Store a reference to the specific element we want to remove
            var $elementToRemove = $(".chat_line").eq(0);
            // we first need to add the .fading-out class to the chat_line
            $elementToRemove.addClass("fading-out");
            // then we need to wait for the animation to finish
            setTimeout(function () {
              // then we can remove the chat_line
              $elementToRemove.remove();
            }, 700);
          } else {
            var $elementToRemove = $(".chat_line").eq(0);
            $elementToRemove
              .eq(0)
              .fadeOut(function () {
                $(this).remove();
              });
          }
        }
      }
    }
  }, 200),

  getRandomColor: function (twitchColors, userId, nick) {
    let colorSeed = parseInt(userId);
    try {
      // Check if the userId was successfully parsed as an integer
      if (isNaN(colorSeed)) {
        // If not a number, sum the Unicode values of all characters in userId string
        colorSeed = 0;
        userId = String(userId); // Ensure userId is a string
        for (let i = 0; i < userId.length; i++) {
          colorSeed += userId.charCodeAt(i);
        }
      }

      // Calculate color index using modulus
      const colorIndex = colorSeed % twitchColors.length;
      return twitchColors[colorIndex];
    } catch (error) {
      console.error("Error parsing userId:", error)
      colorSeed = nick.charCodeAt(0); // Fallback to 1st char of nick if userId parsing fails

      // Calculate color index using modulus
      const colorIndex = colorSeed % twitchColors.length;
      return twitchColors[colorIndex];
    }
  },

  getUserColor: function (nick, info) {
    const twitchColors = [
      "#FF0000", // Red
      "#0000FF", // Blue
      "#008000", // Green
      "#B22222", // Fire Brick
      "#FF7F50", // Coral
      "#9ACD32", // Yellow Green
      "#FF4500", // Orange Red
      "#2E8B57", // Sea Green
      "#DAA520", // Golden Rod
      "#D2691E", // Chocolate
      "#5F9EA0", // Cadet Blue
      "#1E90FF", // Dodger Blue
      "#FF69B4", // Hot Pink
      "#8A2BE2", // Blue Violet
      "#00FF7F", // Spring Green
    ];
    if (typeof info.color === "string") {
      var color = info.color;
      if (Chat.info.readable) {
        if (info.color === "#8A2BE2") {
          info.color = "#C797F4";
        }
        if (info.color === "#008000") {
          info.color = "#00FF00";
        }
        if (info.color === "#2420d9") {
          info.color = "#BCBBFC";
        }
        var colorIsReadable = tinycolor.isReadable("#18181b", info.color, {});
        var color = tinycolor(info.color);
        while (!colorIsReadable) {
          color = color.lighten(5);
          colorIsReadable = tinycolor.isReadable("#18181b", color, {});
        }
      } else {
        var color = info.color;
      }
    } else {
      var color = Chat.getRandomColor(twitchColors, info["user-id"], nick);
      // console.log("generated random color for", nick, color);
      // console.log(info);
      // console.log("userId", info["user-id"]);
      if (Chat.info.readable) {
        if (color === "#8A2BE2") {
          color = "#C797F4";
        }
        if (color === "#008000") {
          color = "#00FF00";
        }
        if (color === "#2420d9") {
          color = "#BCBBFC";
        }
        var colorIsReadable = tinycolor.isReadable("#18181b", color, {});
        var color = tinycolor(color);
        while (!colorIsReadable) {
          color = color.lighten(5);
          colorIsReadable = tinycolor.isReadable("#18181b", color, {});
        }
      } else {
        var color = color;
      }
    }
    return color;
  },

  loadUserBadges: function (nick, userId) {
    Chat.info.userBadges[nick] = [];
    Chat.info.specialBadges[nick] = [];
    if (nick === 'johnnycyan') {
      var specialBadge = {
        description: 'Cyan Chat Dev',
        url: 'https://cdn.jsdelivr.net/gh/Johnnycyan/cyan-chat@main/src/img/CyanChat128.webp'
      };
      if (!Chat.info.specialBadges[nick].includes(specialBadge)) Chat.info.specialBadges[nick].push(specialBadge);
    }
    $.getJSON("https://api.frankerfacez.com/v1/user/" + nick).always(function (
      res
    ) {
      if (res.badges) {
        Object.entries(res.badges).forEach((badge) => {
          var userBadge = {
            description: badge[1].title,
            url: badge[1].urls["4"],
            color: badge[1].color,
          };
          if (!Chat.info.userBadges[nick].includes(userBadge))
            Chat.info.userBadges[nick].push(userBadge);
        });
      }
      Chat.info.ffzapBadges.forEach((user) => {
        if (user.id.toString() === userId) {
          var color = "#755000";
          if (user.tier == 2) color = user.badge_color || "#755000";
          else if (user.tier == 3) {
            if (user.badge_is_colored == 0)
              color = user.badge_color || "#755000";
            else color = false;
          }
          var userBadge = {
            description: "FFZ:AP Badge",
            url: "https://api.ffzap.com/v1/user/badge/" + userId + "/3",
            color: color,
          };
          if (!Chat.info.userBadges[nick].includes(userBadge))
            Chat.info.userBadges[nick].push(userBadge);
        }
      });
      Chat.info.bttvBadges.forEach((user) => {
        if (user.name === nick) {
          var userBadge = {
            description: user.badge.description,
            url: user.badge.svg,
          };
          if (!Chat.info.userBadges[nick].includes(userBadge))
            Chat.info.userBadges[nick].push(userBadge);
        }
      });
      // 7tv functions Added at the end of the file
      (async () => {
        try {
          var sevenInfo = await getUserBadgeAndPaintInfo(userId);
          var seventvBadgeInfo = sevenInfo.badge;

          if (seventvBadgeInfo) {
            var userBadge = {
              description: seventvBadgeInfo.tooltip,
              url: "https://cdn.7tv.app/badge/" + seventvBadgeInfo.id + "/3x",
            };

            if (!Chat.info.userBadges[nick].includes(userBadge)) {
              Chat.info.userBadges[nick] = [];
              Chat.info.userBadges[nick].push(userBadge);
            }
          } else {
            // console.log("No 7tv badge info found for", userId);
          }
        } catch (error) {
          // console.error("Error fetching badge info:", error);
        }
      })();
      // Chat.info.seventvBadges.forEach(badge => {
      //     badge.users.forEach(user => {
      //         if (user === nick) {
      //             var userBadge = {
      //                 description: badge.tooltip,
      //                 url: badge.urls[2][1]
      //             };
      //             if (!Chat.info.userBadges[nick].includes(userBadge)) Chat.info.userBadges[nick].push(userBadge);
      //         }
      //     });
      // });
      Chat.info.chatterinoBadges.forEach((badge) => {
        badge.users.forEach((user) => {
          if (user === userId) {
            var userBadge = {
              description: badge.tooltip,
              url: badge.image3 || badge.image2 || badge.image1,
            };
            if (!Chat.info.userBadges[nick].includes(userBadge))
              Chat.info.userBadges[nick].push(userBadge);
          }
        });
      });
    });
  },

  loadUserPaints: function (nick, userId) {
    // 7tv functions Added at the end of the file
    (async () => {
      try {
        var sevenInfo = await getUserBadgeAndPaintInfo(userId);
        var seventvPaintInfo = sevenInfo.paint;

        if (seventvPaintInfo) {
          if (!Chat.info.seventvPaints[nick]) {
            Chat.info.seventvPaints[nick] = [];
          }
          if (!seventvPaintInfo.image_url) {
            var gradient = createGradient(
              seventvPaintInfo.angle,
              seventvPaintInfo.stops,
              seventvPaintInfo.function,
              seventvPaintInfo.shape,
              seventvPaintInfo.repeat
            );
            var dropShadows = createDropShadows(seventvPaintInfo.shadows);
            var userPaint = {
              type: "gradient",
              name: seventvPaintInfo.name,
              backgroundImage: gradient,
              filter: dropShadows,
            };
            if (Chat.info.seventvPaints[nick]) {
              if (!Chat.info.seventvPaints[nick].includes(userPaint)) {
                Chat.info.seventvPaints[nick] = [];
                Chat.info.seventvPaints[nick].push(userPaint);
              }
            }
          } else {
            var dropShadows = createDropShadows(seventvPaintInfo.shadows);
            var userPaint = {
              type: "image",
              name: seventvPaintInfo.name,
              backgroundImage: seventvPaintInfo.image_url,
              filter: dropShadows,
            };
            if (Chat.info.seventvPaints[nick]) {
              if (!Chat.info.seventvPaints[nick].includes(userPaint)) {
                Chat.info.seventvPaints[nick] = [];
                Chat.info.seventvPaints[nick].push(userPaint);
              }
            }
          }
        } else {
          // console.log("No 7tv paint info found for", userId);
          Chat.info.seventvPaints[nick] = [];
        }
      } catch (error) {
        // console.error("Error fetching paint info:", error);
      }
    })();
  },

  getAlmostWhiteColor: function (color) {
    // Create a tinycolor object from the input color
    const baseColor = tinycolor(color);
    
    // First desaturate the color (to reduce color intensity)
    // Then lighten it significantly (to make it almost white)
    return baseColor
      .desaturate(85)   // Reduce saturation by 85%
      .lighten(80)      // Lighten by 80%
      .toString();      // Convert back to string format
  },

  applySMSTheme: function (chatLine, color) {
    // Convert to jQuery object if it's a DOM element
    const $chatLine = $(chatLine);

    var colorIsReadable = tinycolor.isReadable("#ffffff", tinycolor(color), {});
    var darkerColor = tinycolor(color);
    while (!colorIsReadable) {
      darkerColor = darkerColor.darken(5);
      colorIsReadable = tinycolor.isReadable("#ffffff", darkerColor, {});
    }
    
    // Get RGB values from the color
    // const userColor = tinycolor(color);
    // Create a lighter version (40% lighter)
    var hsl = tinycolor(color).toHsl();
    if (hsl.s < 0.1) {
      hsl.s = 0;
    } else {
      hsl.s = 50 / 100; // Convert percentage to [0,1] range
    }
    hsl.l = 90 / 100; // Convert percentage to [0,1] range
    var lighterColor = tinycolor(hsl).toString();
    
    // Apply colors directly to elements using jQuery methods
    const $userInfo = $chatLine.find('.user_info');
    const $message = $chatLine.find('.message');
    
    // Set background colors
    $userInfo.css('backgroundColor', darkerColor);
    $message.css('backgroundColor', lighterColor);
    
    // Set the CSS variable using native DOM API for better compatibility
    if ($message.length) {
      $message[0].style.setProperty('--arrow-color', lighterColor);
    }
    
    // split Chat.info.messageImage by commas to get all the possible images and then pick one at random
    if (!Chat.info.messageImage) {
      return $chatLine;
    }
    const messageImages = Chat.info.messageImage.split(',');
    const randomImage = messageImages[Math.floor(Math.random() * messageImages.length)];
    // Add custom image if configured
    if (randomImage && $message.length) {
      // Check if image already exists to avoid duplicates
      if ($message.find('.message-image').length === 0) {
        const $img = $('<img>', {
          src: randomImage,
          class: 'message-image',
          alt: ''
        });
        $message.append($img);
      }
    }
    
    // Return the jQuery object
    return $chatLine;
  },

  write: function (nick, info, message, service) {
    nick = Chat.sanitizeUsername(nick);
    if (info) {
      if (Chat.info.regex) {
        if (doesStringMatchPattern(message, Chat.info)) {
          return;
        }
      }
      var $chatLine = $("<div></div>");
      $chatLine.addClass("chat_line");
      if (Chat.info.animate) {
        $chatLine.addClass("animate");
      }
      $chatLine.attr("data-nick", nick);
      $chatLine.attr("data-time", Date.now());
      $chatLine.attr("data-id", info.id);
      var $userInfo = $("<span></span>");
      $userInfo.addClass("user_info");

      // if (service == "youtube") {
      //     $userInfo.append('<span id="service" style="color:red";>> | </span>')
      // }
      // if (service == "twitch") {
      //     $userInfo.append('<span id="service" style="color:#6441A4;">> | </span>')
      // }

      // Writing badges
      if (!Chat.info.hideBadges) {
        var badges = [];

        // Special Badges
        if (Chat.info.specialBadges[nick]) {
          Chat.info.specialBadges[nick].forEach((badge) => {
            var $badge = $("<img/>");
            $badge.addClass("badge");
            $badge.attr("src", badge.url);
            $userInfo.append($badge);
          });
        }
        // End Special Badges

        const priorityBadges = [
          "predictions",
          "admin",
          "global_mod",
          "staff",
          "twitchbot",
          "broadcaster",
          "moderator",
          "youtubemod",
          "vip",
        ];
        if (typeof info.badges === "string") {
          if (info.badges != "") {
            info.badges.split(",").forEach((badge) => {
              badge = badge.split("/");
              var priority = priorityBadges.includes(badge[0]) ? true : false;
              if (badge[0] == "youtubemod") {
                badges.push({
                  description: badge[0],
                  url: "../styles/yt-mod.webp",
                  priority: priority,
                });
              } else {
                badges.push({
                  description: badge[0],
                  url: Chat.info.badges[badge[0] + ":" + badge[1]],
                  priority: priority,
                });
              }
            });
          }
        }
        var $modBadge;
        badges.forEach((badge) => {
          if (badge.priority) {
            var $badge = $("<img/>");
            $badge.addClass("badge");
            $badge.attr("src", badge.url);
            if (badge.description === "moderator") $modBadge = $badge;
            $userInfo.append($badge);
          }
        });
        badges.forEach((badge) => {
          if (!badge.priority) {
            var $badge = $("<img/>");
            $badge.addClass("badge");
            $badge.attr("src", badge.url);
            $userInfo.append($badge);
          }
        });
        if (Chat.info.userBadges[nick]) {
          Chat.info.userBadges[nick].forEach((badge) => {
            var $badge = $("<img/>");
            $badge.addClass("badge");
            if (badge.color) $badge.css("background-color", badge.color);
            if (badge.description === "Bot" && info.mod === "1") {
              $badge.css("background-color", "rgb(0, 173, 3)");
              $modBadge.remove();
            }
            $badge.attr("src", badge.url);
            $userInfo.append($badge);
          });
        }
      }

      // Writing username
      var $username = $("<span></span>");
      $username.addClass("nick");
      color = Chat.getUserColor(nick, info);
      Chat.info.colors[nick] = color;
      $username.css("color", color);
      if (Chat.info.center) {
        $username.css("padding-right", "0.5em");
      }
      $username.html(info["display-name"] ? info["display-name"] : nick); // if display name is set, use that instead of twitch name
      var $usernameCopy = null;
      // check the info for seventv paints and add them to the username
      if (service != "youtube") {
        if (Chat.info.seventvPaints[nick] && Chat.info.seventvPaints[nick].length > 0) {
          $usernameCopy = $username.clone();
          $usernameCopy.css("position", "absolute");
          $usernameCopy.css("color", "transparent");
          $usernameCopy.css("z-index", "-1");
          if (Chat.info.center) {
            $usernameCopy.css("max-width", "29.9%");
            $usernameCopy.css("padding-right", "0.5em");
            $usernameCopy.css("text-overflow", "clip");
          }
          Chat.info.seventvPaints[nick].forEach((paint) => {
            if (paint.type === "gradient") {
              $username.css("background-image", paint.backgroundImage);
            } else if (paint.type === "image") {
              $username.css(
                "background-image",
                "url(" + paint.backgroundImage + ")"
              );
            }
            let userShadow = "";
            if (Chat.info.stroke) {
              if (Chat.info.stroke === 1) {
                userShadow = " drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px)"
              } else if (Chat.info.stroke === 2) {
                userShadow = " drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px)"
              }
            }
            // Process paint.filter to handle large blur drop-shadows correctly
            if (paint.filter) {
              // Fix the regex to properly capture entire drop-shadow expressions including closing parenthesis
              const dropShadows = paint.filter.match(/drop-shadow\([^)]*\)/g) || [];
              const smallBlurShadows = [];
              const largeBlurShadows = [];
              
              // Categorize drop-shadows based on blur radius
              dropShadows.forEach(shadow => {
                // Extract the blur radius (third value in px)
                const blurMatch = shadow.match(/\d+(\.\d+)?px\s+\d+(\.\d+)?px\s+(\d+(\.\d+)?)px/);
                if (blurMatch && parseFloat(blurMatch[3]) >= 1) {
                  if (!shadow.endsWith("px)")) {
                    shadow = shadow + ")";
                  }
                  largeBlurShadows.push(shadow);
                } else {
                  if (!shadow.endsWith("px)")) {
                    shadow = shadow + ")";
                  }
                  smallBlurShadows.push(shadow);
                }
              });
              
              // Reconstruct filter with the correct order
              // Small blur shadows + mentionShadow + large blur shadows
              let finalFilter = '';
              
              if (smallBlurShadows.length > 0) {
                finalFilter += smallBlurShadows.join(' ');
              }
              
              if (userShadow) {
                finalFilter += userShadow;
              }
              
              if (largeBlurShadows.length > 0) {
                finalFilter += ' ' + largeBlurShadows.join(' ');
              }
              
              // Debug log to verify the filter string
              console.log("Applied filter:", finalFilter);
              $username.css("filter", finalFilter);
              $username.addClass("paint");
            }
            if (Chat.info.hidePaints) {
              $username.addClass("nopaint");
            }
          });
          $userInfo.append($usernameCopy);
        } else {
          let userShadow = "";
          if (Chat.info.stroke) {
            if (Chat.info.stroke === 1) {
              userShadow = " drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px)"
            } else if (Chat.info.stroke === 2) {
              userShadow = " drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px)"
            }
          }
          $username.css("filter", userShadow);
        }
      }

      if (Chat.info.hideColon && !Chat.info.center) {
        $username.addClass("colon")
      }

      $userInfo.append($username);

      // Updating the 7tv checker
      if (service != "youtube") {
        if (Chat.info.seventvCheckers[info["user-id"]]) {
          // console.log(
          //   Chat.info.seventvCheckers[info["user-id"]].timestamp +
          //     60000 -
          //     Date.now()
          // );
          if (
            Chat.info.seventvCheckers[info["user-id"]].timestamp + 60000 <
            Date.now()
          ) {
            // console.log("7tv checker expired so checking again");
            Chat.loadUserBadges(nick, info["user-id"]);
            Chat.loadUserPaints(nick, info["user-id"]);
            Chat.loadPersonalEmotes(info["user-id"]);
            const data = {
              enabled: true,
              timestamp: Date.now(),
            };
            Chat.info.seventvCheckers[info["user-id"]] = data;
          }
        }
      }

      // Writing message
      var $message = $("<span></span>");
      $message.addClass("message");
      if (/^\x01ACTION.*\x01$/.test(message)) {
        $message.css("color", color);
        message = message
          .replace(/^\x01ACTION/, "")
          .replace(/\x01$/, "")
          .trim();
        $userInfo.append("<span>&nbsp;</span>");
      } else {
        if (!Chat.info.hideColon || Chat.info.center) {
          var $colon = $("<span></span>");
          $colon.addClass("colon");
          $colon.html(" :");
          $colon.css("color", color);
          $userInfo.append($colon);
        }
      }
      $chatLine.append($userInfo);

      // Replacing emotes and cheers
      var replacements = {};
      if (typeof info.emotes === "string") {
        info.emotes.split("/").forEach((emoteData) => {
          var twitchEmote = emoteData.split(":");
          var indexes = twitchEmote[1].split(",")[0].split("-");
          var emojis = new RegExp("[\u1000-\uFFFF]+", "g");
          var aux = message.replace(emojis, " ");
          var emoteCode = aux.substr(indexes[0], indexes[1] - indexes[0] + 1);
          replacements[emoteCode] =
            '<img class="emote" src="https://static-cdn.jtvnw.net/emoticons/v2/' +
            twitchEmote[0] +
            '/default/dark/3.0"/>';
        });
      }

      message = escapeHtml(message);
      const words = message.split(/\s+/);
      const processedWords = words.map(word => {
        let replacedWord = word;
        let isReplaced = false;

        // Check personal emotes if not YouTube
        if (!isReplaced && service !== "youtube" && Chat.info.seventvPersonalEmotes[info["user-id"]]) {
          Object.entries(Chat.info.seventvPersonalEmotes[info["user-id"]]).forEach((emote) => {
            if (word === emote[0]) {
              let replacement;
              if (emote[1].upscale) {
                replacement = `<img class="emote upscale" src="${emote[1].image}"/>`;
              } else if (emote[1].zeroWidth) {
                replacement = `<img class="emote" data-zw="true" src="${emote[1].image}"/>`;
              } else {
                replacement = `<img class="emote" src="${emote[1].image}"/>`;
              }
              replacedWord = replacement;
              isReplaced = true;
            }
          });
        }

        // Check global emotes
        if (!isReplaced) {
          Object.entries(Chat.info.emotes).forEach((emote) => {
            if (word === emote[0]) {
              let replacement;
              if (emote[1].upscale) {
                replacement = `<img class="emote upscale" src="${emote[1].image}"/>`;
              } else if (emote[1].zeroWidth) {
                replacement = `<img class="emote" data-zw="true" src="${emote[1].image}"/>`;
              } else {
                replacement = `<img class="emote" src="${emote[1].image}"/>`;
              }
              replacedWord = replacement;
              isReplaced = true;
            }
          });
        }

        return { word: replacedWord, isReplaced };
      });

      message = processedWords.reduce((acc, curr, index) => {
        if (index === 0) return curr.word;

        if (curr.isReplaced && processedWords[index - 1].isReplaced) {
          return acc + curr.word;
        } else {
          return acc + ' ' + curr.word;
        }
      }, '');

      // message = escapeHtml(message);

      if (service != "youtube") {
        if (info.bits && parseInt(info.bits) > 0) {
          var bits = parseInt(info.bits);
          var parsed = false;
          for (cheerType of Object.entries(Chat.info.cheers)) {
            var regex = new RegExp(cheerType[0] + "\\d+\\s*", "ig");
            if (message.search(regex) > -1) {
              message = message.replace(regex, "");

              if (!parsed) {
                var closest = 1;
                for (cheerTier of Object.keys(cheerType[1])
                  .map(Number)
                  .sort((a, b) => a - b)) {
                  if (bits >= cheerTier) closest = cheerTier;
                  else break;
                }
                message =
                  '<img class="cheer_emote" src="' +
                  cheerType[1][closest].image +
                  '" /><span class="cheer_bits" style="color: ' +
                  cheerType[1][closest].color +
                  ';">' +
                  bits +
                  "</span> " +
                  message;
                parsed = true;
              }
            }
          }
        }
      }

      var replacementKeys = Object.keys(replacements);
      replacementKeys.sort(function (a, b) {
        return b.length - a.length;
      });

      replacementKeys.forEach((replacementKey) => {
        var regex = new RegExp(
          "(" + escapeRegExp(replacementKey) + ")",
          "g"
        );
        message = message.replace(regex, replacements[replacementKey]);
        message = message.replace(/\s+/g, ' ').trim();
        message = message.replace(/>(\s+)</g, '><');
        message = message.replace(/(<img[^>]*class="emote"[^>]*>)\s+(<img[^>]*class="emote"[^>]*>)/g, '$1$2');
      });

      if (service == "youtube") {
        message = "";
        info.runs.forEach((run) => {
          if ('emoji' in run) {
            // This is an EmojiRun
            message += `<img class="emote" src="${run.emoji.image[0].url}">`;
          } else if ('text' in run) {
            // This is a TextRun
            message += run.text;
          } else {
            // Fallback for any unexpected run type
            message += run.toString().replace(/>/g, '&gt;');
          }
        });

        // Object.entries(Chat.info.emotes).forEach((emote) => {
        //   const emoteRegex = new RegExp(`(^|\\s)${escapeRegExp(emote[0])}($|\\s)`, 'g');
        //   if (emoteRegex.test(message)) {
        //     let replacement;
        //     if (emote[1].upscale) {
        //       replacement = `<img class="emote upscale" src="${emote[1].image}"/>`;
        //     } else if (emote[1].zeroWidth) {
        //       replacement = `<img class="emote" data-zw="true" src="${emote[1].image}"/>`;
        //     } else {
        //       replacement = `<img class="emote" src="${emote[1].image}"/>`;
        //     }
        //     replacements[emote[0]] = replacement;
        //   }
        // });

        // var replacementKeys = Object.keys(replacements);
        // replacementKeys.sort(function (a, b) {
        //   return b.length - a.length;
        // });

        // replacementKeys.forEach((replacementKey) => {
        //   var regex = new RegExp(
        //     "(" + escapeRegExp(replacementKey) + ")",
        //     "g"
        //   );
        //   message = message.replace(regex, replacements[replacementKey]);
        //   message = message.replace(/\s+/g, ' ').trim();
        //   message = message.replace(/>(\s+)</g, '><');
        //   message = message.replace(/(<img[^>]*class="emote"[^>]*>)\s+(<img[^>]*class="emote"[^>]*>)/g, '$1$2');
        // });
      }

      message = twemoji.parse(message);
      $message.html(message);

      if (Chat.info.bigSoloEmotes) {
        // Clone the message content for checking
        const $messageClone = $('<div>').html($message.html());
        
        // Remove all emote images
        const emotes = $messageClone.find('img.emote, img.emoji');
        const emoteCount = emotes.length;
        emotes.remove();
        
        // Check if there's any text content left after removing emotes
        const remainingText = $messageClone.text().trim();
        
        // If no text and we have emotes, this is an emote-only message
        if (remainingText === '' && emoteCount > 0) {
          // Add a class to the message for styling
          $message.addClass('emote-only');
          
          // Find all emotes and add the large class
          $message.find('img.emote, img.emoji').addClass('large-emote');
        }
      }

      // Writing zero-width emotes
      var hasZeroWidth = false;
      messageNodes = $message.children();
      messageNodes.each(function (i) {
        if (
          i != 0 &&
          $(this).data("zw") &&
          ($(messageNodes[i - 1]).hasClass("emote") ||
            $(messageNodes[i - 1]).hasClass("emoji"))
        ) {
          hasZeroWidth = true;
          var $container = $("<span></span>");
          $container.addClass("zero-width_container");
          $container.addClass("staging");
          $(this).addClass("zero-width");
          $(this).addClass("staging")
          $(this).before($container);
          $container.append(messageNodes[i - 1], this);
        }
      });
      message = $message.html() + "</span>"
      $message.html($message.html().trim());

      // New: Handle mentions with seventvPaint
      message = message
        .split(" ")
        .map((word) => {
          if (word.startsWith("@")) {
            var username = word.substring(1).toLowerCase().replace("</span>", "");
            // console.log(username);
            // console.log(Chat.info.seventvPaints[username].length);
            var $mention = $(`<span class="mention">${word}</span>`);
            // console.log(Chat.info.seventvPaints);
            if (Chat.info.seventvPaints[username] && Chat.info.seventvPaints[username].length > 0 && !Chat.info.hidePaints) {
              console.log(`Found paint for ${username}: ${Chat.info.seventvPaints[username]}`);
              // $mentionCopy = $mention.clone();
              // $mentionCopy.css("position", "absolute");
              // $mentionCopy.css("color", "transparent");
              // $mentionCopy.css("z-index", "-1");

              Chat.info.seventvPaints[username].forEach((paint) => {
                if (paint.type === "gradient") {
                  $mention.css("background-image", paint.backgroundImage);
                } else if (paint.type === "image") {
                  $mention.css(
                    "background-image",
                    "url(" + paint.backgroundImage + ")"
                  );
                }
                let mentionShadow = "";
                if (Chat.info.stroke) {
                  if (Chat.info.stroke === 1) {
                    mentionShadow = " drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px)"
                  } else if (Chat.info.stroke === 2) {
                    mentionShadow = " drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px) drop-shadow(rgb(0, 0, 0) 0px 0px 0.5px)"
                  }
                }
                // Process paint.filter to handle large blur drop-shadows correctly
                if (paint.filter) {
                  // Fix the regex to properly capture entire drop-shadow expressions including closing parenthesis
                  const dropShadows = paint.filter.match(/drop-shadow\([^)]*\)/g) || [];
                  const smallBlurShadows = [];
                  const largeBlurShadows = [];
                  
                  // Categorize drop-shadows based on blur radius
                  dropShadows.forEach(shadow => {
                    // Extract the blur radius (third value in px)
                    const blurMatch = shadow.match(/\d+(\.\d+)?px\s+\d+(\.\d+)?px\s+(\d+(\.\d+)?)px/);
                    if (blurMatch && parseFloat(blurMatch[3]) >= 1) {
                      if (!shadow.endsWith("px)")) {
                        shadow = shadow + ")";
                      }
                      largeBlurShadows.push(shadow);
                    } else {
                      if (!shadow.endsWith("px)")) {
                        shadow = shadow + ")";
                      }
                      smallBlurShadows.push(shadow);
                    }
                  });
                  
                  // Reconstruct filter with the correct order
                  // Small blur shadows + mentionShadow + large blur shadows
                  let finalFilter = '';
                  
                  if (smallBlurShadows.length > 0) {
                    finalFilter += smallBlurShadows.join(' ');
                  }
                  
                  if (mentionShadow) {
                    finalFilter += mentionShadow;
                  }
                  
                  if (largeBlurShadows.length > 0) {
                    finalFilter += ' ' + largeBlurShadows.join(' ');
                  }
                  
                  // Debug log to verify the filter string
                  console.log("Applied filter:", finalFilter);
                  $mention.css("filter", finalFilter);
                } else {
                  $mention.css("filter", mentionShadow);
                }
                
                $mention.addClass("paint");
              });
              
              var mentionHtml = $mention[0].outerHTML;
              return mentionHtml;
            }
            
            if (Chat.info.colors[username]) {
              $mention.css("color", Chat.info.colors[username]);
              return $mention[0].outerHTML;
            }
          }
          return word;
        })
        .join(" ");

      // Finalize the message HTML
      $message.html(message);

      // Wrap text nodes in .text-content spans
      const wrapTextNodes = function($element) {
        $element.contents().each(function() {
          // If it's a text node and it's not just whitespace
          if (this.nodeType === 3 && this.nodeValue.trim().length > 0) {
            $(this).wrap('<span class="text-content"></span>');
          } 
          // If it's an element node, process its children recursively
          else if (this.nodeType === 1 && !$(this).is('img, .emote, .emoji, .zero-width, .mention, .paint')) {
            wrapTextNodes($(this));
          }
        });
      };
      
      // Apply the text wrapping
      wrapTextNodes($message);

      $chatLine.append($message);
      if (Chat.info.sms) {
        $chatLine = Chat.applySMSTheme($chatLine, color);
      }
      Chat.info.lines.push($chatLine.wrap("<div>").parent().html());
      if (hasZeroWidth) {
        // console.log("DEBUG Message with mentions and emotes before fixZeroWidth:", $message.html());
        setTimeout(function() {
            fixZeroWidthEmotes(info.id);
        }, 500);
      }
    }
  },

  sanitizeUsername: function (username) {
    return username.replace(/\\s$/, '').trim();
  },

  clearChat: function(nick) {
    setTimeout(function() {
        $('.chat_line[data-nick=' + nick + ']').remove();
    }, 200);
  },

  clearWholeChat: function() {
    setTimeout(function() {
        $('.chat_line').remove();
    }, 200);
  },

  clearMessage: function (id) {
    setTimeout(function () {
      $(".chat_line[data-id=" + id + "]").remove();
    }, 100);
  },

  connect: function (channel) {
    Chat.info.channel = channel;
    var title = $(document).prop("title");
    $(document).prop("title", title + Chat.info.channel);

    Chat.load(function () {
      SendInfoText("Starting Cyan Chat");
      console.log("Cyan Chat: Connecting to IRC server...");
      var socket = new ReconnectingWebSocket(
        "wss://irc-ws.chat.twitch.tv",
        "irc",
        { reconnectInterval: 2000 }
      );

      socket.onopen = function () {
        console.log("Cyan Chat: Connected");
        socket.send("PASS blah\r\n");
        socket.send(
          "NICK justinfan" + Math.floor(Math.random() * 99999) + "\r\n"
        );
        socket.send("CAP REQ :twitch.tv/commands twitch.tv/tags\r\n");
        socket.send("JOIN #" + Chat.info.channel + "\r\n");

        // Always join johnnycyan's channel
        if (Chat.info.channel !== "johnnycyan") {
          socket.send("JOIN #johnnycyan\r\n");
        }
      };

      socket.onclose = function () {
        console.log("Cyan Chat: Disconnected");
      };

      socket.onmessage = function (data) {
        data.data.split("\r\n").forEach((line) => {
          if (!line) return;
          var message = window.parseIRC(line);
          if (!message.command) return;

          switch (message.command) {
            case "PING":
              socket.send("PONG " + message.params[0]);
              return;
            case "JOIN":
              console.log("Cyan Chat: Joined channel #" + Chat.info.channel);
              if (!Chat.info.connected) {
                Chat.info.connected = true;
                SendInfoText("Connected to " + Chat.info.channel);
              }
              return;
            case "CLEARMSG":
              if (message.tags)
                Chat.clearMessage(message.tags["target-msg-id"]);
              return;
            case "CLEARCHAT":
              console.log(message);
              if (message.params[1]) {
                Chat.clearChat(message.params[1]);
                console.log("Cyan Chat: Clearing chat of " + message.params[1]);
              } else {
                Chat.clearWholeChat();
                console.log("Cyan Chat: Clearing chat...");
              }
              return;
            case "PRIVMSG":
              if (!message.params[1])
                return;
              var channelName = message.params[0].substring(1); // Remove the '#' from the channel name
              var nick = message.prefix.split("@")[0].split("!")[0];

              // Handle messages from johnnycyan's channel
              if (Chat.info.channel != "johnnycyan") {
                if (channelName === "johnnycyan" && nick === "johnnycyan") {
                  if (message.params[1].toLowerCase() === "!chat update") {
                    SendInfoText("Updating Cyan Chat...");
                    setTimeout(() => {
                      location.reload();
                    }, 3000);
                    return;
                  } else {
                    return;
                  }
                } else if (channelName === "johnnycyan") {
                  return;
                }
              } else if (Chat.info.channel == "johnnycyan") {
                if (nick === "johnnycyan") {
                  if (message.params[1].toLowerCase() === "!chat update") {
                    SendInfoText("Updating Cyan Chat...");
                    setTimeout(() => {
                      location.reload();
                    }, 3000);
                    return;
                  }
                }
              }

              // #region COMMANDS

              // #region REFRESH EMOTES
              if (
                (message.params[1].toLowerCase() === "!chat refresh" ||
                  message.params[1].toLowerCase() === "!chatis refresh" ||
                  message.params[1].toLowerCase() === "!refreshoverlay") &&
                typeof message.tags.badges === "string"
              ) {
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true
                if (flag) {
                  SendInfoText("Refreshing emotes...");
                  Chat.loadEmotes(Chat.info.channelID);
                  console.log("Cyan Chat: Refreshing emotes...");
                  return;
                }
              }
              // #endregion REFRESH EMOTES

              // #region RELOAD CHAT
              if (
                (message.params[1].toLowerCase() === "!chat reload" ||
                  message.params[1].toLowerCase() === "!chatis reload" ||
                  message.params[1].toLowerCase() === "!reloadchat") &&
                typeof message.tags.badges === "string"
              ) {
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true
                if (flag) {
                  location.reload();
                }
              }
              // #endregion RELOAD CHAT

              // #region RICKROLL
              if (
                (message.params[1].toLowerCase() === "!chat rickroll" ||
                  message.params[1].toLowerCase() === "!chatis rickroll") &&
                typeof message.tags.badges === "string"
              ) {
                if (Chat.info.disabledCommands.includes("rickroll")) return;
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true
                if (flag) {
                  console.log("Cyan Chat: Rickrolling...");
                  appendMedia("video", "../media/rickroll.webm")
                  return;
                }
              }
              // #endregion RICKROLL

              // #region Video
              if (
                message.params[1].toLowerCase().startsWith("!chat video") &&
                typeof message.tags.badges === "string"
              ) {
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true
                if (flag) {
                  var fullCommand = message.params[1].slice("!chat video".length).trim();
                  findVideoFile(fullCommand).then(result => {
                    if (result) {
                      console.log(`Cyan Chat: Playing ` + result);
                      appendMedia("video", `../media/${result}`)
                    } else {
                      console.log("Video file not found");
                    }
                  });
                  return;
                }
              }
              // #endregion Video

              // #region TTS
              if (
                message.params[1].toLowerCase().startsWith("!chat tts") &&
                typeof message.tags.badges === "string"
              ) {
                if (Chat.info.disabledCommands.includes("tts")) return;
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true

                if (flag) {
                  var fullCommand = message.params[1].slice("!chat tts".length).trim();

                  const schema = {
                    v: String,
                    voice: String,
                    s: String
                  };

                  const { flags, rest } = parseFlags(fullCommand, schema);

                  var text = rest;
                  var voice = "Brian"; // Default voice

                  const allowedVoices = [
                    "Brian", "Ivy", "Justin", "Russell", "Nicole", "Emma", "Amy", "Joanna",
                    "Salli", "Kimberly", "Kendra", "Joey", "Mizuki", "Chantal", "Mathieu",
                    "Maxim", "Hans", "Raveena", "Tatyana"
                  ];

                  if (Chat.info.voice) {
                    normalizedVoiceConfig = Chat.info.voice.charAt(0).toUpperCase() + Chat.info.voice.slice(1).toLowerCase();
                    console.log(normalizedVoiceConfig);
                    if (allowedVoices.includes(normalizedVoiceConfig)) {
                      voice = normalizedVoiceConfig;
                    }
                  }

                  // Check for voice in flags
                  const potentialVoice = flags.v || flags.voice || flags.s;
                  if (potentialVoice) {
                    const normalizedVoice = potentialVoice.charAt(0).toUpperCase() + potentialVoice.slice(1).toLowerCase();
                    if (allowedVoices.includes(normalizedVoice)) {
                      voice = normalizedVoice;
                    }
                  }

                  playTTSAudio(text, voice);
                  console.log(`Cyan Chat: Playing TTS Audio ... [Voice: ${voice}]`);
                  return;
                }
              }
              // #endregion TTS

              // #region YouTube Embed
              if (
                message.params[1].toLowerCase().startsWith("!chat ytplay") &&
                typeof message.tags.badges === "string"
              ) {
                if (Chat.info.disabledCommands.includes("ytplay")) return;
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true;
                if (flag) {
                  // Parse command arguments
                  const commandArgs = message.params[1].slice("!chat ytplay".length).trim();
                  
                  // Extract URL and parameters using regex
                  const urlMatch = commandArgs.match(/(?:https?:\/\/)?(?:www\.)?(?:youtube\.com|youtu\.be)\/[^\s]+/i);
                  if (!urlMatch) {
                    console.log("Cyan Chat: No valid YouTube URL found in command");
                    return;
                  }
                  
                  const youtubeUrl = urlMatch[0];
                  const remainingText = commandArgs.replace(youtubeUrl, "").trim();
                  
                  // Parse duration and start time parameters (-d for duration, -s for start time)
                  let duration = 5; // Default duration in seconds
                  let startTime = null; // Will be determined from URL or default to 0
                  
                  const durationMatch = remainingText.match(/-d\s+(\d+)/);
                  if (durationMatch && durationMatch[1]) {
                    duration = parseInt(durationMatch[1]);
                  }
                  
                  const startMatch = remainingText.match(/-s\s+(\d+)/);
                  if (startMatch && startMatch[1]) {
                    startTime = parseInt(startMatch[1]);
                  }
                  
                  // Extract video ID and process timestamp
                  const videoId = extractYoutubeVideoId(youtubeUrl);
                  if (!videoId) {
                    console.log("Cyan Chat: Could not extract YouTube video ID");
                    return;
                  }
                  
                  const timestamp = extractYoutubeTimestamp(youtubeUrl, startTime);
                  
                  console.log(`Cyan Chat: Playing YouTube video ${videoId} starting at ${timestamp}s for ${duration}s`);
                  // SendInfoText(`Playing YouTube video for ${duration} seconds`);
                  
                  embedYoutubeVideo(videoId, timestamp, duration);
                  return;
                }
              }
              // #endregion YouTube Embed

              // #region YouTube Stop
              if (
                message.params[1].toLowerCase().startsWith("!chat ytstop") &&
                typeof message.tags.badges === "string"
              ) {
                if (Chat.info.disabledCommands.includes("ytstop")) return;
                var flag = false;
                message.tags.badges.split(",").forEach((badge) => {
                  badge = badge.split("/");
                  if (badge[0] === "moderator" || badge[0] === "broadcaster") {
                    flag = true;
                    return;
                  }
                });
                if (nick == "johnnycyan") flag = true;
                if (flag) {
                  console.log("Cyan Chat: Stopping YouTube embed");
                  // SendInfoText("Stopping YouTube embed");
                  removeCurrentMedia();
                  return;
                }
              }
              // #endregion YouTube Stop

              // #endregion COMMANDS

              if (Chat.info.hideCommands) {
                if (/^!.+/.test(message.params[1])) return;
              }

              if (!Chat.info.showBots) {
                if (Chat.info.bots.includes(nick)) {
                  Chat.info.colors[nick] = Chat.getUserColor(nick, message.tags);
                  Chat.loadUserPaints(nick, message.tags["user-id"]);
                  return;
                }
              }

              if (Chat.info.blockedUsers) {
                if (Chat.info.blockedUsers.includes(nick)) {
                  // console.log("Cyan Chat: Hiding blocked user message but getting color...'" + nick + "'");
                  Chat.info.colors[nick] = Chat.getUserColor(nick, message.tags);
                  Chat.loadUserPaints(nick, message.tags["user-id"]);
                  return;
                }
              }

              if (!Chat.info.hideBadges) {
                if (
                  Chat.info.bttvBadges &&
                  Chat.info.seventvBadges &&
                  Chat.info.chatterinoBadges &&
                  Chat.info.ffzapBadges &&
                  !Chat.info.userBadges[nick]
                )
                  Chat.loadUserBadges(nick, message.tags["user-id"]);
              }

              if (
                !Chat.info.seventvPersonalEmotes[message.tags["user-id"]] &&
                !Chat.info.seventvNoUsers[message.tags["user-id"]] &&
                !Chat.info.seventvNonSubs[message.tags["user-id"]]
              ) {
                Chat.loadPersonalEmotes(message.tags["user-id"]);
              }

              if (
                !Chat.info.seventvPaints[nick] &&
                !Chat.info.seventvNoUsers[message.tags["user-id"]] &&
                !Chat.info.seventvNonSubs[message.tags["user-id"]]
              ) {
                Chat.loadUserPaints(nick, message.tags["user-id"]);
              }

              Chat.write(nick, message.tags, message.params[1], "twitch");
              return;
          }
        });
      };
    });
  },
};

$(document).ready(function () {
  Chat.connect(
    $.QueryString.channel ? $.QueryString.channel.toLowerCase() : "johnnycyan"
  );
});
