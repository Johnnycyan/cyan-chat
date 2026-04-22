function fadeOption(event) {
    if ($fade_bool.is(":checked")) {
        // Show fade seconds input with a smooth transition
        $fade.removeClass("hidden").css({
            'opacity': 0,
            'transform': 'translateY(-5px)'
        }).animate({
            'opacity': 1,
            'transform': 'translateY(0)'
        }, 300);

        $fade_seconds.removeClass("hidden").css({
            'opacity': 0
        }).animate({
            'opacity': 1
        }, 300);
    } else {
        // Hide fade seconds with a smooth transition
        $fade.animate({
            'opacity': 0,
            'transform': 'translateY(-5px)'
        }, 300, function () {
            $(this).addClass("hidden");
        });

        $fade_seconds.animate({
            'opacity': 0
        }, 300, function () {
            $(this).addClass("hidden");
        });
    }
}

// New Popup Manager
const popup = {
    elements: {
        overlay: document.getElementById('popupOverlay'),
        container: document.getElementById('popupContainer'),
        title: document.getElementById('popupTitle'),
        content: document.getElementById('popupContent'),
        closeBtn: document.getElementById('popupClose')
    },

    // Configuration for different popups
    types: {
        'emote-sync': {
            title: 'Emote Sync',
            contentId: 'emote-sync-content'
        },
        'message-pruning': {
            title: 'Message Pruning',
            contentId: 'message-pruning-content'
        },
        'sms-theme': {
            title: 'SMS Theme',
            contentId: 'sms-theme-content'
        }
    },

    // Open popup with specific type
    open: function (type) {
        if (!this.types[type]) return;

        // Set popup content
        this.elements.title.textContent = this.types[type].title;
        const contentTemplate = document.getElementById(this.types[type].contentId);

        if (contentTemplate) {
            this.elements.content.innerHTML = contentTemplate.innerHTML;
        }

        // Show and animate popup
        this.elements.overlay.classList.add('active');

        // Delay the container animation slightly for a nicer effect
        setTimeout(() => {
            this.elements.container.classList.add('active');
        }, 50);
    },

    // Close popup
    close: function () {
        this.elements.container.classList.remove('active');

        // Wait for animation to finish before hiding the overlay
        setTimeout(() => {
            this.elements.overlay.classList.remove('active');
        }, 300);
    },

    // Initialize the popup system
    init: function () {
        // Close button click
        this.elements.closeBtn.addEventListener('click', () => this.close());

        // Click outside to close
        this.elements.overlay.addEventListener('click', (e) => {
            if (e.target === this.elements.overlay) {
                this.close();
            }
        });

        // Escape key to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.elements.overlay.classList.contains('active')) {
                this.close();
            }
        });
    }
};

// Initialize popup when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    popup.init();
    initializeAnimations();
    setupFormTransition();
    generateCustomPronounColorInputs();
    initTabs();

    Coloris({
        el: '.coloris',
        swatches: [
            '#264653',
            '#2a9d8f',
            '#e9c46a',
            '#f4a261',
            '#e76f51',
            '#d62828',
            '#023e8a',
            '#0077b6',
            '#0096c7',
            '#00b4d8',
            '#48cae4'
        ]
    });

    /** Instances **/

    // Extract unique colors from pronoun defaults
    const pronounColors = [
        "#4facfe", "#00f2fe", "#ff9a9e", "#fecfef", "#a8edea", "#fed6e3",
        "#fee140", "#a8caba", "#8a74ae", "#667eea", "#9f5edf", "#ffeef1",
        "#f093fb", "#7cc2ff", "#43e97b", "#38f9d7", "#fa709a", "#9d64d6",
        "#f5576c"
    ];

    Coloris.setInstance('.instance1', {
        theme: 'pill',
        themeMode: 'dark',
        alpha: false,
        swatches: pronounColors
    });

    // Initialize pronoun settings
    pronounsUpdate();

    // Initial preview load
    updatePreview();
});

// Unified popup show function
function showPopup(type) {
    popup.open(type);
}

function fontUpdate() {
    if ($font.val() === "12") {
        $custom_font.prop("disabled", false);
    } else {
        $custom_font.prop("disabled", true);
    }
    updatePreview();
}

var disabledCommands = [];
function commandsUpdate(event) {
    disabledCommands = [];
    const commandCheckboxes = {
        'tts': $disableTTS,
        'rickroll': $disableRickroll,
        'ytplay': $disableYTPlay,
        'ytstop': $disableYTStop,
        'img': $disableIMG
    };

    // Iterate through all command checkboxes
    Object.entries(commandCheckboxes).forEach(([command, $checkbox]) => {
        if ($checkbox.is(":checked")) {
            disabledCommands.push(command);
        }
    });
}

function smsUpdate() {
    if ($sms.is(":checked")) {
        $center.prop("disabled", true);
        if ($center.is(":checked")) { $center.prop("checked", false); }
        $normalChat.prop("disabled", true);
        if ($normalChat.is(":checked")) { $normalChat.prop("checked", false); }
        $paints.prop("disabled", true).prop("checked", true);
        $colon.prop("disabled", true).prop("checked", false);
        $invert.prop("disabled", true).prop("checked", false);
        $stroke.prop("disabled", true).val("0");
        $shadow.prop("disabled", true).val("0");
        $(".message-image-field").slideDown();
    } else {
        $center.prop("disabled", false);
        $normalChat.prop("disabled", false);
        $paints.prop("disabled", false).prop("checked", false);
        $colon.prop("disabled", false);
        $invert.prop("disabled", false);
        $stroke.prop("disabled", false);
        $shadow.prop("disabled", false);
        $(".message-image-field").slideUp();
    }
    updatePreview();
}

function centerUpdate() {
    if ($center.is(":checked")) {
        $normalChat.prop("disabled", true);
        if ($normalChat.is(":checked")) { $normalChat.prop("checked", false); }
        $sms.prop("disabled", true);
        if ($sms.is(":checked")) {
            $sms.prop("checked", false);
            $(".message-image-field").slideUp();
        }
    } else {
        $sms.prop("disabled", false);
        $normalChat.prop("disabled", false);
    }
    updatePreview();
}

function resetForm() {
    $channel.val("");
    $ytChannel.val("");
    $regex.val("");
    $blockedUsers.val("");
    $allowedUsers.val("");
    $size.val("3");
    $emoteScale.val("1");
    $scale.val("1");
    $font.val("0");
    $height.val("3");
    $voice.val("Brian");
    $stroke.val("0");
    $weight.val("4");
    $shadow.val("0");
    $bots.prop("checked", false);
    $commands.prop("checked", false);
    $badges.prop("checked", false);
    $paints.prop("checked", false);
    $colon.prop("checked", false);
    $animate.prop("checked", true);
    $fade_bool.prop("checked", false);
    $fade.addClass("hidden");
    $fade_seconds.addClass("hidden");
    $fade.val("30");
    $small_caps.prop("checked", false);
    $invert.prop("checked", false);
    $center.prop("checked", false);
    $readable.prop("checked", true);
    $sync.prop("checked", false);
    $pruning.prop("checked", false);
    $pronouns.prop("checked", false);
    $pronounColorMode.val("default");
    $pronounColorMode.prop("disabled", true);
    $('.pronoun-color-field').hide();
    $(".pronoun-sub-options").hide();
    $custom_font.prop("disabled", true);
    $sms.prop("checked", false);
    $messageImage.val("");
    $(".message-image-field").hide();
    $disableTTS.prop("checked", false);
    $disableRickroll.prop("checked", false);
    $ytEmotes.prop("checked", true);
    $disableYTPlay.prop("checked", false);
    $disableYTStop.prop("checked", false);
    $disableIMG.prop("checked", false);
    $bigEmotes.prop("checked", false);
    $highlight.prop("checked", true);
    $gigantify.prop("checked", true);
    $showRedeems.prop("checked", true);
    $highlightMentions.prop("checked", false);
    $highlightMentionColor.val("#ffff00");
    $(".highlight-mention-color-field").hide();
    $normalChat.prop("checked", false);

    // Re-enable all disabled fields
    $center.prop("disabled", false);
    $normalChat.prop("disabled", false);
    $paints.prop("disabled", false);
    $colon.prop("disabled", false);
    $invert.prop("disabled", false);
    $stroke.prop("disabled", false);
    $shadow.prop("disabled", false);
    $sms.prop("disabled", false);
    disabledCommands = [];

    $result.addClass("hidden");
    $generator.removeClass("hidden");
    showUrl();
    updatePreview();
}

// Add animations and UI enhancements

// Initialize UI animations
function initializeAnimations() {
    // Add ripple effect to buttons
    const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"]');

    buttons.forEach(button => {
        button.addEventListener('click', function (e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const ripple = document.createElement('span');
            ripple.style.position = 'absolute';
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            ripple.style.transform = 'translate(-50%, -50%) scale(0)';
            ripple.style.width = '0';
            ripple.style.height = '0';
            ripple.style.backgroundColor = 'rgba(255, 255, 255, 0.3)';
            ripple.style.borderRadius = '50%';
            ripple.style.transition = 'all 0.5s';
            ripple.style.pointerEvents = 'none';

            this.appendChild(ripple);

            setTimeout(() => {
                ripple.style.width = '200px';
                ripple.style.height = '200px';
                ripple.style.transform = 'translate(-50%, -50%) scale(1)';
                ripple.style.opacity = '0';
            }, 10);

            setTimeout(() => {
                ripple.remove();
            }, 500);
        });
    });

    // Add shimmer effect to form sections
    const formSections = document.querySelectorAll('.form-section');
    let delay = 0;

    formSections.forEach(section => {
        section.style.animation = `fadeInDown 0.6s ease ${delay}s both`;
        delay += 0.1;
    });

    // Animate details elements
    const detailsElements = document.querySelectorAll('details');

    detailsElements.forEach(details => {
        details.addEventListener('toggle', function () {
            const content = this.querySelector('.details-content');
            if (this.open) {
                content.style.animation = 'none';
                // Trigger reflow
                void content.offsetWidth;
                content.style.animation = 'fadeInDown 0.3s';
            }
        });
    });
}

// Nice transition when form is submitted
function setupFormTransition() {
    const form = document.querySelector('form[name="generator"]');
    const result = document.getElementById('result');

    if (form && result) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();

            // Scroll to top smoothly
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });

            // Add exit animation to form
            form.style.animation = 'fadeOut 0.5s forwards';

            setTimeout(() => {
                form.classList.add('hidden');
                result.classList.remove('hidden');
                result.style.animation = 'fadeIn 0.5s forwards';

                // Generate URL
                generateURL(e);
            }, 500);
        });
    }
}

function generateURL(event) {
    event.preventDefault();

    const baseUrl = window.location.href;
    const url = new URL(baseUrl);
    let currentUrl = url.origin + url.pathname;
    currentUrl = currentUrl.replace(/\/+$/, "");

    var generatedUrl = "";
    if ($regex.val() == "") {
        generatedUrl = currentUrl + "/v2/?channel=" + $channel.val();
    } else {
        generatedUrl =
            currentUrl +
            "/v2/?channel=" +
            $channel.val() +
            "&regex=" +
            encodeURIComponent($regex.val());
    }

    var selectedFont;
    if ($font.val() === "12") {
        selectedFont = $custom_font.val();
    } else {
        selectedFont = $font.val();
    }

    let data = {
        size: $size.val(),
        emoteScale: $emoteScale.val(),
        scale: $scale.val() != "1" ? $scale.val() : false,
        font: selectedFont,
        height: $height.val(),
        voice: $voice.val(),
        stroke: $stroke.val() != "0" ? $stroke.val() : false,
        weight: $weight.val() != "4" ? $weight.val() : false,
        shadow: $shadow.val() != "0" ? $shadow.val() : false,
        bots: $bots.is(":checked"),
        hide_commands: $commands.is(":checked"),
        hide_badges: $badges.is(":checked"),
        hide_paints: $paints.is(":checked"),
        pronouns: $pronouns.is(":checked"),
        hide_colon: $colon.is(":checked"),
        animate: $animate.is(":checked"),
        fade: $fade_bool.is(":checked") ? $fade.val() : false,
        small_caps: $small_caps.is(":checked"),
        invert: $invert.is(":checked"),
        center: $center.is(":checked"),
        readable: $readable.is(":checked"),
        disable_sync: $sync.is(":checked"),
        disable_pruning: $pruning.is(":checked"),
        block: $blockedUsers.val().replace(/\s+/g, ""),
        allow: $allowedUsers.val().replace(/\s+/g, ""),
        yt: $ytChannel.val().replace('@', ''),
        yt_emotes: !$ytEmotes.is(":checked") ? "false" : false,
        sms: $sms.is(":checked"),
        message_image: $sms.is(":checked") ? $messageImage.val() : false,
        big_emotes: $bigEmotes.is(":checked"),
        off_commands: disabledCommands.length > 0 ? disabledCommands.join(",") : false,
        pronoun_color_mode: $pronounColorMode.val() !== "default" ? $pronounColorMode.val() : false,
        pronoun_single_color1: $pronounColorMode.val() === "single" ? $pronounColor1.val() : false,
        pronoun_single_color2: $pronounColorMode.val() === "single" ? $pronounColor2.val() : false,
        pronoun_custom_colors: $pronounColorMode.val() === "custom" ? getPronounCustomColors() : false,
        highlight: !$highlight.is(":checked") ? "false" : false,
        gigantify: !$gigantify.is(":checked") ? "false" : false,
        show_redeems: !$showRedeems.is(":checked") ? "false" : false,
        highlight_mentions: $highlightMentions.is(":checked"),
        highlight_mention_color: $highlightMentions.is(":checked") ? $highlightMentionColor.val().replace("#", "") : false,
        normal_chat: $normalChat.is(":checked"),
    };

    const params = encodeQueryData(data);

    $url.val(generatedUrl + "&" + params);
}

function backToForm() {
    const result = document.getElementById('result');
    const form = document.querySelector('form[name="generator"]');

    result.style.animation = 'fadeOut 0.5s forwards';

    setTimeout(() => {
        result.classList.add('hidden');
        form.classList.remove('hidden');
        form.style.animation = 'fadeIn 0.5s forwards';
        $alert.css("visibility", "hidden");
    }, 500);
}

function copyUrl() {
    navigator.clipboard.writeText($url.val());

    $alert.css({
        "visibility": "visible",
        "opacity": "1",
    });

    $alert.css("animation", "justFadeIn 0.6s");

    setTimeout(() => {
        showUrl();
    }, 2000);
}

function showUrl() {
    $alert.css({
        "opacity": "0",
        "visibility": "hidden",
        "animation": "justFadeOut 0.6s"
    });
}

// Preview iframe update (debounced)
let previewTimeout = null;
function updatePreview() {
    clearTimeout(previewTimeout);
    previewTimeout = setTimeout(function () {
        const $frame = $('#preview-frame');
        if (!$frame.length) return;

        var selectedFont;
        if ($font.val() === "12") {
            selectedFont = $custom_font.val();
        } else {
            selectedFont = $font.val();
        }

        let data = {
            preview: true,
            channel: 'cyanchat',
            size: $size.val(),
            emoteScale: $emoteScale.val(),
            font: selectedFont,
            height: $height.val(),
            stroke: $stroke.val() != "0" ? $stroke.val() : false,
            weight: $weight.val() != "4" ? $weight.val() : false,
            shadow: $shadow.val() != "0" ? $shadow.val() : false,
            bots: true,
            hide_commands: $commands.is(":checked"),
            hide_badges: $badges.is(":checked"),
            hide_paints: $paints.is(":checked"),
            pronouns: $pronouns.is(":checked"),
            hide_colon: $colon.is(":checked"),
            animate: $animate.is(":checked"),
            fade: false,
            small_caps: $small_caps.is(":checked"),
            invert: $invert.is(":checked"),
            center: $center.is(":checked"),
            readable: $readable.is(":checked"),
            disable_sync: $sync.is(":checked"),
            disable_pruning: true,
            sms: $sms.is(":checked"),
            message_image: $sms.is(":checked") ? ($messageImage.val() || false) : false,
            big_emotes: $bigEmotes.is(":checked"),
            off_commands: disabledCommands.length > 0 ? disabledCommands.join(",") : false,
            pronoun_color_mode: $pronounColorMode.val() !== "default" ? $pronounColorMode.val() : false,
            pronoun_single_color1: $pronounColorMode.val() === "single" ? $pronounColor1.val() : false,
            pronoun_single_color2: $pronounColorMode.val() === "single" ? $pronounColor2.val() : false,
            pronoun_custom_colors: $pronounColorMode.val() === "custom" ? getPronounCustomColors() : false,
            highlight: !$highlight.is(":checked") ? "false" : false,
            gigantify: !$gigantify.is(":checked") ? "false" : false,
            show_redeems: !$showRedeems.is(":checked") ? "false" : false,
            highlight_mentions: $highlightMentions.is(":checked"),
            highlight_mention_color: $highlightMentions.is(":checked") ? $highlightMentionColor.val().replace("#", "") : false,
            normal_chat: $normalChat.is(":checked"),
        };

        const params = encodeQueryData(data);
        $frame.attr('src', 'v2/?' + params);
    }, 500);
}

function togglePreviewBackground() {
    document.getElementById('preview-container').classList.toggle('light-bg');
}

// Tab switching
function initTabs() {
    $('.tab-btn').on('click', function () {
        const tabId = $(this).data('tab');
        $('.tab-btn').removeClass('active');
        $(this).addClass('active');
        $('.tab-content').removeClass('active');
        $('#tab-' + tabId).addClass('active');
    });
}

const $generator = $("form[name='generator']");
const $channel = $('input[name="channel"]');
const $ytChannel = $('input[name="yt-channel"]');
const $animate = $('input[name="animate"]');
const $bots = $('input[name="bots"]');
const $fade_bool = $("input[name='fade_bool']");
const $fade = $("input[name='fade']");
const $fade_seconds = $("#fade_seconds");
const $commands = $("input[name='commands']");
const $small_caps = $("input[name='small_caps']");
const $invert = $('input[name="invert"]');
const $center = $('input[name="center"]');
const $readable = $('input[name="readable"]');
const $sync = $('input[name="sync"]');
const $pruning = $('input[name="pruning"]');
const $badges = $("input[name='badges']");
const $paints = $("input[name='paints']");
const $pronouns = $("input[name='pronouns']");
const $colon = $("input[name='colon']");
const $size = $("select[name='size']");
const $emoteScale = $("select[name='emote_scale']");
const $scale = $("select[name='scale']");
const $font = $("select[name='font']");
const $height = $("select[name='height']");
const $voice = $("select[name='voice']");
const $custom_font = $("input[name='custom_font']");
const $stroke = $("select[name='stroke']");
const $weight = $("select[name='weight']");
const $shadow = $("select[name='shadow']");
const $result = $("#result");
const $url = $("#url");
const $alert = $("#alert");
const $reset = $("#reset");
const $goBack = $("#go-back");
const $regex = $('input[name="regex"]');
const $blockedUsers = $('input[name="blocked_users"]');
const $allowedUsers = $('input[name="allowed_users"]');
const $sms = $('input[name="sms"]');
const $messageImage = $('input[name="message_image"]');
const $bigEmotes = $('input[name="big_emotes"]');
const $disableTTS = $('input[name="disable_tts"]');
const $disableRickroll = $('input[name="disable_rickroll"]');
const $ytEmotes = $('input[name="yt_emotes"]');
const $disableYTPlay = $('input[name="disable_ytplay"]');
const $disableYTStop = $('input[name="disable_ytstop"]');
const $disableIMG = $('input[name="disable_img"]');
const $pronounColorMode = $('select[name="pronoun_color_mode"]');
const $pronounColor1 = $('input[name="pronoun_single_color1"]');
const $pronounColor2 = $('input[name="pronoun_single_color2"]');
const $highlight = $('input[name="highlight"]');
const $gigantify = $('input[name="gigantify"]');
const $showRedeems = $('input[name="show_redeems"]');
const $highlightMentions = $('input[name="highlight_mentions"]');
const $highlightMentionColor = $('input[name="highlight_mention_color"]');
const $normalChat = $('input[name="normal_chat"]');

// Specific handlers for options with interdependencies
$fade_bool.change(fadeOption);
$font.change(fontUpdate);
$center.change(centerUpdate);
$sms.change(smsUpdate);
$normalChat.change(normalChatUpdate);
$pronouns.change(pronounsUpdate);
$pronounColorMode.change(pronounColorModeUpdate);
$highlightMentions.change(highlightMentionsUpdate);
$disableTTS.change(commandsUpdate);
$disableRickroll.change(commandsUpdate);
$disableYTPlay.change(commandsUpdate);
$disableYTStop.change(commandsUpdate);
$disableIMG.change(commandsUpdate);
$generator.submit(generateURL);
$url.click(copyUrl);
$alert.click(showUrl);
$reset.click(resetForm);
$goBack.click(backToForm);

// Generic handler: any form change triggers preview update
$('form[name="generator"] select, form[name="generator"] input').on('change input', function () {
    if ($(this).attr('name') === 'channel' || $(this).attr('name') === 'yt-channel') return;
    updatePreview();
});

function normalChatUpdate() {
    if ($normalChat.is(":checked")) {
        $center.prop("disabled", true);
        if ($center.is(":checked")) { $center.prop("checked", false); }
        $sms.prop("disabled", true);
        if ($sms.is(":checked")) {
            $sms.prop("checked", false);
            $(".message-image-field").slideUp();
        }
    } else {
        $center.prop("disabled", false);
        $sms.prop("disabled", false);
    }
    updatePreview();
}

function highlightMentionsUpdate() {
    if ($highlightMentions.is(":checked")) {
        $(".highlight-mention-color-field").slideDown();
    } else {
        $(".highlight-mention-color-field").slideUp();
    }
    updatePreview();
}

function pronounsUpdate() {
    const isChecked = $pronouns.is(":checked");
    $pronounColorMode.prop('disabled', !isChecked);

    if (isChecked) {
        $(".pronoun-sub-options").slideDown();
        pronounColorModeUpdate();
    } else {
        $(".pronoun-sub-options").slideUp();
        $('.pronoun-color-field').hide();
    }
    updatePreview();
}

function pronounColorModeUpdate() {
    const mode = $pronounColorMode.val();
    $('.pronoun-color-field').hide();

    if ($pronouns.is(":checked")) {
        if (mode === 'single') {
            $('#single-gradient-field').show();
        } else if (mode === 'custom') {
            $('#custom-colors-field').show();
        }
    }
    updatePreview();
}

function generateCustomPronounColorInputs() {
    const pronounTypes = [
        { display: "He/Him", name: "hehim", default1: "#4facfe", default2: "#00f2fe" },
        { display: "She/Her", name: "sheher", default1: "#ff9a9e", default2: "#fecfef" },
        { display: "They/Them", name: "theythem", default1: "#a8edea", default2: "#fed6e3" },
        { display: "She/They", name: "shethem", default1: "#ff9a9e", default2: "#fee140" },
        { display: "He/They", name: "hethem", default1: "#4facfe", default2: "#fed6e3" },
        { display: "He/She", name: "heshe", default1: "#4facfe", default2: "#ff9a9e" },
        { display: "Xe/Xem", name: "xexem", default1: "#a8caba", default2: "#8a74ae" },
        { display: "Fae/Faer", name: "faefaer", default1: "#667eea", default2: "#9f5edf" },
        { display: "Ve/Ver", name: "vever", default1: "#ffeef1", default2: "#f093fb" },
        { display: "Ae/Aer", name: "aeaer", default1: "#7cc2ff", default2: "#00f2fe" },
        { display: "Zie/Hir", name: "ziehir", default1: "#43e97b", default2: "#38f9d7" },
        { display: "Per/Per", name: "perper", default1: "#fa709a", default2: "#fee140" },
        { display: "E/Em", name: "eem", default1: "#667eea", default2: "#9d64d6" },
        { display: "It/Its", name: "itits", default1: "#f093fb", default2: "#f5576c" }
    ];

    const container = $('#pronoun-color-inputs');
    const singleContainer = $('#single-gradient-field');
    container.empty();

    pronounTypes.forEach(pronoun => {
        const html = `
            <div style="display: flex; align-items: center; gap: 5px; margin-bottom: 8px; font-size: 16px;">
                <div class="pronoun-label" style="width: 140px; text-align: center; cursor: pointer;" data-pronoun="${pronoun.name}" data-default1="${pronoun.default1}" data-default2="${pronoun.default2}" title="Click to reset to default colors">
                    <span class="pronoun ${pronoun.name}" style="padding: 0.2em 0.5em; border-radius: 0.8em; color: black; font-size:16px;">${pronoun.display}</span>
                </div>
                <div class="color-picker square">
                    <input type="text" name="pronoun_${pronoun.name}_color1" class="coloris instance1" value="${pronoun.default1}" style="height: 25px;"/>
                </div>
                <div class="color-picker square">
                    <input type="text" name="pronoun_${pronoun.name}_color2" class="coloris instance1" value="${pronoun.default2}" style="height: 25px;"/>
                </div>
            </div>
        `;
        container.append(html);
    });

    // Add click handler for pronoun labels to reset colors
    container.find('.pronoun-label').on('click', function () {
        console.log("Resetting pronoun colors for " + $(this).data('pronoun'));
        const pronounName = $(this).data('pronoun');
        const default1 = $(this).data('default1');
        const default2 = $(this).data('default2');

        $(`input[name="pronoun_${pronounName}_color1"]`).val(default1);
        $(`input[name="pronoun_${pronounName}_color2"]`).val(default2);

        document.querySelector(`input[name="pronoun_${pronounName}_color1"]`).dispatchEvent(new Event('input', { bubbles: true }));
        document.querySelector(`input[name="pronoun_${pronounName}_color2"]`).dispatchEvent(new Event('input', { bubbles: true }));

        updatePronounColors();
    });

    // Add click handler for single gradient label to reset colors
    singleContainer.find('.pronoun-label').on('click', function () {
        console.log("Resetting single gradient colors");
        const default1 = $(this).data('default1');
        const default2 = $(this).data('default2');

        $pronounColor1.val(default1);
        $pronounColor2.val(default2);

        document.querySelector(`input[name="pronoun_single_color1"]`).dispatchEvent(new Event('input', { bubbles: true }));
        document.querySelector(`input[name="pronoun_single_color2"]`).dispatchEvent(new Event('input', { bubbles: true }));

        updatePronounColors();
    });

    // Add event listeners for the new color inputs
    document.addEventListener('coloris:pick', event => {
        updatePronounColors();
    });
    // container.find('input[type="text"]').on('change', updatePronounColors);
}

function updatePronounColors() {
    updatePreview();
}

function getPronounCustomColors() {
    const pronounTypes = ['hehim', 'sheher', 'theythem', 'shethem', 'hethem', 'heshe', 'xexem', 'faefaer', 'vever', 'aeaer', 'ziehir', 'perper', 'eem', 'itits'];
    const colors = {};

    pronounTypes.forEach(type => {
        const color1Input = $(`input[name="pronoun_${type}_color1"]`);
        const color2Input = $(`input[name="pronoun_${type}_color2"]`);

        if (color1Input.length && color2Input.length) {
            colors[type] = {
                color1: color1Input.val(),
                color2: color2Input.val()
            };
        }
    });

    return JSON.stringify(colors);
}