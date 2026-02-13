package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/polly"
	"github.com/gorilla/websocket"
	"github.com/nicklaw5/helix/v2"
)

type ActiveChannels struct {
	Count          int               `json:"count"`
	Channels       map[string]string `json:"channels"`
	AllTimeHighest int               `json:"all_time_highest"`
	UniqueUsers    map[string]bool   `json:"unique_users"`
}

var (
	pollySvc       *polly.Polly
	voiceMap       map[string]string
	mu             sync.Mutex
	activeChannels ActiveChannels
	activeMutex    sync.Mutex
	tokens         map[string]string
	AdminPassword  string
)

// ============================================================
// Shared Chat EventSub Types & State
// ============================================================

// SharedChatParticipant represents a channel in a shared chat session
type SharedChatParticipant struct {
	UserID    string `json:"broadcaster_user_id"`
	UserName  string `json:"broadcaster_user_name"`
	UserLogin string `json:"broadcaster_user_login"`
}

// SharedChatEvent is the JSON sent to frontend SSE clients
type SharedChatEvent struct {
	Type         string                `json:"type"` // "begin", "update", "end"
	SessionID    string                `json:"session_id"`
	HostID       string                `json:"host_id"`
	HostLogin    string                `json:"host_login"`
	Participants []SharedChatParticipant `json:"participants,omitempty"`
}

// EventSubChannel tracks an EventSub WS connection for one broadcaster
type EventSubChannel struct {
	ChannelID  string
	Conn       *websocket.Conn
	SessionID  string
	SSEClients map[chan SharedChatEvent]bool
	SSEMutex   sync.Mutex
	Cancel     context.CancelFunc
}

var (
	eventSubChannels = make(map[string]*EventSubChannel)
	eventSubMutex    sync.RWMutex
)

func init() {
	// Create an AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-north-1"), // Change this to your preferred region
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create AWS session: %v", err))
	}

	// Create Polly client
	pollySvc = polly.New(sess)

	// Initialize voice map
	voiceMap = map[string]string{
		"Brian":    "Brian",
		"Ivy":      "Ivy",
		"Justin":   "Justin",
		"Russell":  "Russell",
		"Nicole":   "Nicole",
		"Emma":     "Emma",
		"Amy":      "Amy",
		"Joanna":   "Joanna",
		"Salli":    "Salli",
		"Kimberly": "Kimberly",
		"Kendra":   "Kendra",
		"Joey":     "Joey",
		"Mizuki":   "Mizuki",
		"Chantal":  "Chantal",
		"Mathieu":  "Mathieu",
		"Maxim":    "Maxim",
		"Hans":     "Hans",
		"Raveena":  "Raveena",
	}

	// Initialize activeChannels
	activeChannels = ActiveChannels{
		Count:          0,
		Channels:       make(map[string]string),
		AllTimeHighest: 0,
	}

	// Load existing active channels from file
	loadTokens()
	loadActiveChannels()
}

func loadTokens() {
	file, err := os.ReadFile("tokens.json")
	if err != nil {
		log.Fatal("Error reading tokens.json:", err)
	}

	err = json.Unmarshal(file, &tokens)
	if err != nil {
		log.Fatal("Error parsing tokens.json:", err)
	}

	AdminPassword = tokens["admin_password"]
}

func loadActiveChannels() {
	file, err := os.ReadFile("active.json")
	if err == nil {
		json.Unmarshal(file, &activeChannels)
	}
}

func saveActiveChannels() {
	file, _ := json.MarshalIndent(activeChannels, "", "  ")
	os.WriteFile("active.json", file, 0644)
}

func updateActiveChannel(channel string) {
	activeMutex.Lock()
	defer activeMutex.Unlock()

	cleanupInactiveChannels()

	activeChannels.Channels[channel] = time.Now().Format(time.RFC3339)
	activeChannels.Count = len(activeChannels.Channels)

	if activeChannels.Count > activeChannels.AllTimeHighest {
		activeChannels.AllTimeHighest = activeChannels.Count
	}

	// Store unique user
	if activeChannels.UniqueUsers == nil {
		activeChannels.UniqueUsers = make(map[string]bool)
	}
	activeChannels.UniqueUsers[channel] = true

	saveActiveChannels()
}

func cleanupInactiveChannels() {
	threshold := time.Now().Add(-3 * time.Minute)
	for channel, lastActive := range activeChannels.Channels {
		lastActiveTime, _ := time.Parse(time.RFC3339, lastActive)
		if lastActiveTime.Before(threshold) {
			delete(activeChannels.Channels, channel)
		}
	}
	activeChannels.Count = len(activeChannels.Channels)
}

func handleActive(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		http.Error(w, "No channel specified", http.StatusBadRequest)
		return
	}

	updateActiveChannel(channel)
	w.WriteHeader(http.StatusOK)
}

func loadTemplate(filename string) (*template.Template, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New(filepath.Base(filename)).Parse(string(content))
	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

func loadTemplateWithFuncMap(filename string, funcMap template.FuncMap) (*template.Template, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New(filepath.Base(filename)).Funcs(funcMap).Parse(string(content))
	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

func handleAdminActive(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := loadTemplate("login.html")
		if err != nil {
			http.Error(w, "Failed to load template", http.StatusInternalServerError)
			return
		}
		// Serve the login form
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		// Handle login
		r.ParseForm()
		password := r.FormValue("password")
		if password != AdminPassword {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		activeMutex.Lock()
		cleanupInactiveChannels()
		activeMutex.Unlock()

		funcMap := template.FuncMap{
			"formatTime": func(t string) string {
				parsedTime, err := time.Parse(time.RFC3339, t)
				if err != nil {
					return "Invalid time"
				}
				duration := time.Since(parsedTime)
				minutes := int(duration.Minutes())

				if minutes < 1 {
					return "<1m ago"
				} else {
					return fmt.Sprintf("%dm ago", minutes)
				}
			},
		}

		tmpl, err := loadTemplateWithFuncMap("admin.html", funcMap)
		if err != nil {
			http.Error(w, "Failed to load template", http.StatusInternalServerError)
			return
		}

		data := struct {
			ActiveChannels
			UniqueUsers []string
		}{
			ActiveChannels: activeChannels,
			UniqueUsers:    make([]string, 0, len(activeChannels.UniqueUsers)),
		}

		for user := range activeChannels.UniqueUsers {
			data.UniqueUsers = append(data.UniqueUsers, user)
		}

		sort.Strings(data.UniqueUsers)

		tmpl.Execute(w, data)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func synthesizeSpeechHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the request is coming from your website
	if !isRequestFromYourWebsite(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get parameters from the request
	voiceName := r.URL.Query().Get("voice")
	text := r.URL.Query().Get("text")

	// Make sure the length of text is under 1000 characters
	if len(text) > 1000 {
		http.Error(w, "Text length exceeds the limit of 1000 characters", http.StatusBadRequest)
		return
	}

	// Convert voice name to Polly voice ID
	voiceID, ok := voiceMap[voiceName]
	if !ok {
		http.Error(w, "Invalid voice name", http.StatusBadRequest)
		return
	}

	// Set up the input parameters
	input := &polly.SynthesizeSpeechInput{
		OutputFormat: aws.String("mp3"),
		Text:         aws.String(text),
		VoiceId:      aws.String(voiceID),
	}

	// Use a mutex to ensure thread-safe access to the Polly client
	mu.Lock()
	output, err := pollySvc.SynthesizeSpeech(input)
	mu.Unlock()

	if err != nil {
		http.Error(w, "Failed to synthesize speech", http.StatusInternalServerError)
		return
	}

	// Read the audio stream
	audioBytes, err := io.ReadAll(output.AudioStream)
	if err != nil {
		http.Error(w, "Failed to read audio stream", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "audio/mpeg")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(audioBytes)))

	// Write the audio data directly to the response
	_, err = w.Write(audioBytes)
	if err != nil {
		http.Error(w, "Failed to write audio data", http.StatusInternalServerError)
		return
	}
}

func isRequestFromYourWebsite(r *http.Request) bool {
	// Check if it's a same-origin request
	origin := r.Header.Get("Origin")
	host := r.Host

	// If Origin is empty, it's likely a same-origin request
	if origin == "" {
		return true
	}

	// If Origin is set, compare it with the Host
	if origin != "" {
		originURL, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return originURL.Host == host
	}

	return false
}

type OAuthResponse struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

var (
	accessToken  string
	refreshToken string
	clientID     string
	clientSecret string
	client       *helix.Client
)

func TwitchOAuthHandler(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", "https://id.twitch.tv/oauth2/validate", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logTwitchError("TwitchOAuthHandler Do", err, "")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Println("Refreshing token")
			err = refreshTokenOnce()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			TwitchOAuthHandler(w, r)
		} else {
			body, _ := io.ReadAll(resp.Body)
			logTwitchError("TwitchOAuthHandler Status", fmt.Errorf("Status %d", resp.StatusCode), string(body))
			http.Error(w, string(body), resp.StatusCode)
			return
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func TwitchGetUserIDforUsernameHandler(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", "https://api.twitch.tv/helix/users?login="+r.URL.Query().Get("username"), nil)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Client-Id", clientID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logTwitchError("TwitchGetUserID Do", err, "")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Println("Refreshing token")
			err = refreshTokenOnce()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			TwitchGetUserIDforUsernameHandler(w, r)
		} else {
			body, _ := io.ReadAll(resp.Body)
			log.Println(string(body))
			logTwitchError("TwitchGetUserID Status", fmt.Errorf("Status %d", resp.StatusCode), string(body))
			http.Error(w, string(body), resp.StatusCode)
			return
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func TwitchAPIHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	req, err := http.NewRequest("GET", "https://api.twitch.tv/helix"+url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Client-Id", clientID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logTwitchError("TwitchAPIHandler Do", err, "")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Println("Refreshing token")
			err = refreshTokenOnce()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			TwitchAPIHandler(w, r)
		} else {
			body, _ := io.ReadAll(resp.Body)
			logTwitchError("TwitchAPIHandler Status", fmt.Errorf("Status %d", resp.StatusCode), string(body))
			http.Error(w, string(body), resp.StatusCode)
			return
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func TwitchRedirectHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code found.", http.StatusBadRequest)
		return
	}

	resp, err := client.RequestUserAccessToken(code)
	if err != nil {
		log.Fatal(err)
	}

	accessToken = resp.Data.AccessToken
	refreshToken = resp.Data.RefreshToken
	saveTokens(accessToken, refreshToken)
}

func handleChatterinoBadges(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers to allow requests from any origin
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")

	// Make a request to the Chatterino API
	resp, err := http.Get("https://api.chatterino.com/badges")
	if err != nil {
		http.Error(w, "Failed to fetch Chatterino badges", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	// Parse the JSON response
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		http.Error(w, "Failed to parse JSON response", http.StatusInternalServerError)
		return
	}

	// Set the content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Send the parsed JSON back to the client
	json.NewEncoder(w).Encode(result)
}

func saveTokens(accessToken string, refreshToken string) {
	file, err := os.Create("tokens.json")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()
	err = json.NewEncoder(file).Encode(map[string]string{
		"access_token":   accessToken,
		"refresh_token":  refreshToken,
		"client_id":      clientID,
		"client_secret":  clientSecret,
		"admin_password": AdminPassword,
	})
	if err != nil {
		log.Fatal(err)
		return
	}
}

func refreshTokenOnce() error {
	resp, err := client.RefreshUserAccessToken(refreshToken)
	if err != nil {
		log.Println("Failed to refresh token: " + err.Error())
		return err
	}
	accessToken = resp.Data.AccessToken
	refreshToken = resp.Data.RefreshToken
	saveTokens(accessToken, refreshToken)
	log.Println("Token Refreshed")
	return nil
}

func refreshTokenLoop() {
	for {
		resp, err := client.RefreshUserAccessToken(refreshToken)
		if err != nil {
			log.Println("Failed to refresh token: " + err.Error())
			time.Sleep(time.Second * 5)
			go refreshTokenLoop()
		}
		accessToken = resp.Data.AccessToken
		refreshToken = resp.Data.RefreshToken
		saveTokens(accessToken, refreshToken)
		log.Println("Token Refreshed")
		time.Sleep(time.Minute * 120)
	}
}

func logTwitchError(context string, err error, body string) {
	f, fileErr := os.OpenFile("twitch_errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		log.Println("Failed to open twitch_errors.log:", fileErr)
		return
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags)
	logger.Printf("[%s] Error: %v | Body: %s\n", context, err, body)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Be careful with this in production
	},
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check if the request is coming from your website
	if !isRequestFromYourWebsite(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract the channel parameter from the request URL
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		log.Println("No channel specified")
		http.Error(w, "No channel specified", http.StatusBadRequest)
		return
	}

	// Upgrade the HTTP connection to a WebSocket connection
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer clientConn.Close()

	// Connect to the YouTube WebSocket using the provided channel
	youtubeConn, _, err := websocket.DefaultDialer.Dial("ws://localhost:9905/c/"+channel, nil)
	if err != nil {
		log.Println("YouTube WebSocket connection error:", err)
		return
	}
	defer youtubeConn.Close()

	// Bidirectional relay
	errChan := make(chan error, 2)
	go func() {
		errChan <- relay(clientConn, youtubeConn, "Client->YouTube", channel)
	}()
	go func() {
		errChan <- relay(youtubeConn, clientConn, "YouTube->Client", channel)
	}()

	// Wait for the first error/closure
	<-errChan
}

func relay(src, dst *websocket.Conn, direction, channelID string) error {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			// Improve "use of closed network connection" check
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Printf("[%s] Channel %s Read error: %v", direction, channelID, err)
			return err
		}
		err = dst.WriteMessage(messageType, message)
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Printf("[%s] Channel %s Write error: %v", direction, channelID, err)
			return err
		}
	}
}

// ============================================================
// Shared Chat EventSub Functions
// ============================================================

// handleSharedChatSubscribe starts EventSub listening for a channel
func handleSharedChatSubscribe(w http.ResponseWriter, r *http.Request) {
	channelID := r.URL.Query().Get("channel_id")
	if channelID == "" {
		http.Error(w, "channel_id required", http.StatusBadRequest)
		return
	}

	eventSubMutex.RLock()
	_, exists := eventSubChannels[channelID]
	eventSubMutex.RUnlock()

	if exists {
		log.Printf("[TEMP DEBUG][SharedChat] EventSub already running for channel %s", channelID)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "already_subscribed"})
		return
	}

	log.Printf("[TEMP DEBUG][SharedChat] Starting EventSub for channel %s", channelID)
	go startEventSubForChannel(channelID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "subscribing"})
}

// handleSharedChatEvents provides an SSE stream of shared chat events
func handleSharedChatEvents(w http.ResponseWriter, r *http.Request) {
	channelID := r.URL.Query().Get("channel_id")
	if channelID == "" {
		http.Error(w, "channel_id required", http.StatusBadRequest)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Create a channel for this SSE client
	eventChan := make(chan SharedChatEvent, 10)

	// Register this client
	eventSubMutex.RLock()
	esc, exists := eventSubChannels[channelID]
	eventSubMutex.RUnlock()

	if !exists {
		// EventSub not started yet, start it
		log.Printf("[TEMP DEBUG][SharedChat] SSE client connected before EventSub started for %s, starting now", channelID)
		go startEventSubForChannel(channelID)

		// Wait briefly for the channel to be created
		for i := 0; i < 50; i++ {
			time.Sleep(100 * time.Millisecond)
			eventSubMutex.RLock()
			esc, exists = eventSubChannels[channelID]
			eventSubMutex.RUnlock()
			if exists {
				break
			}
		}
		if !exists {
			http.Error(w, "Failed to start EventSub", http.StatusInternalServerError)
			return
		}
	}

	esc.SSEMutex.Lock()
	esc.SSEClients[eventChan] = true
	esc.SSEMutex.Unlock()

	log.Printf("[TEMP DEBUG][SharedChat] SSE client connected for channel %s", channelID)

	// Send initial connected event
	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	// Stream events
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			esc.SSEMutex.Lock()
			delete(esc.SSEClients, eventChan)
			remainingClients := len(esc.SSEClients)
			esc.SSEMutex.Unlock()
			log.Printf("[TEMP DEBUG][SharedChat] SSE client disconnected for channel %s (%d clients remaining)", channelID, remainingClients)

			// If no more SSE clients, stop EventSub after a grace period
			if remainingClients == 0 {
				go func() {
					time.Sleep(30 * time.Second) // Grace period for reconnects
					eventSubMutex.RLock()
					currentEsc, exists := eventSubChannels[channelID]
					eventSubMutex.RUnlock()
					if !exists {
						return
					}
					currentEsc.SSEMutex.Lock()
					clientCount := len(currentEsc.SSEClients)
					currentEsc.SSEMutex.Unlock()
					if clientCount == 0 {
						log.Printf("[TEMP DEBUG][SharedChat] No SSE clients for channel %s after grace period, stopping EventSub", channelID)
						stopEventSubForChannel(channelID)
					}
				}()
			}
			return
		case event := <-eventChan:
			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("[TEMP DEBUG][SharedChat] Error marshaling SSE event: %v", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// broadcastToSSEClients sends a SharedChatEvent to all SSE clients for a channel
func broadcastToSSEClients(esc *EventSubChannel, event SharedChatEvent) {
	esc.SSEMutex.Lock()
	defer esc.SSEMutex.Unlock()

	log.Printf("[TEMP DEBUG][SharedChat] Broadcasting %s event to %d SSE clients for channel %s",
		event.Type, len(esc.SSEClients), esc.ChannelID)

	for ch := range esc.SSEClients {
		select {
		case ch <- event:
		default:
			// Client channel full, skip
			log.Printf("[TEMP DEBUG][SharedChat] SSE client channel full, skipping")
		}
	}
}

// startEventSubForChannel connects to Twitch EventSub WS and subscribes to shared chat events
func startEventSubForChannel(channelID string) {
	ctx, cancel := context.WithCancel(context.Background())

	esc := &EventSubChannel{
		ChannelID:  channelID,
		SSEClients: make(map[chan SharedChatEvent]bool),
		Cancel:     cancel,
	}

	eventSubMutex.Lock()
	if _, exists := eventSubChannels[channelID]; exists {
		eventSubMutex.Unlock()
		cancel()
		return
	}
	eventSubChannels[channelID] = esc
	eventSubMutex.Unlock()

	defer func() {
		eventSubMutex.Lock()
		delete(eventSubChannels, channelID)
		eventSubMutex.Unlock()
		cancel()
		log.Printf("[TEMP DEBUG][SharedChat] EventSub stopped for channel %s", channelID)
	}()

	connectURL := "wss://eventsub.wss.twitch.tv/ws"

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[TEMP DEBUG][SharedChat] Connecting to EventSub WS for channel %s at %s", channelID, connectURL)

		conn, _, err := websocket.DefaultDialer.Dial(connectURL, nil)
		if err != nil {
			log.Printf("[TEMP DEBUG][SharedChat] EventSub WS connection error for %s: %v", channelID, err)
			time.Sleep(5 * time.Second)
			connectURL = "wss://eventsub.wss.twitch.tv/ws" // Reset to default URL on error
			continue
		}
		esc.Conn = conn

		// Read welcome message
		err = processEventSubMessages(ctx, esc, conn, channelID, &connectURL)
		conn.Close()

		if err != nil {
			log.Printf("[TEMP DEBUG][SharedChat] EventSub WS error for %s: %v, reconnecting...", channelID, err)
			time.Sleep(5 * time.Second)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// processEventSubMessages reads and handles messages from the EventSub WS
func processEventSubMessages(ctx context.Context, esc *EventSubChannel, conn *websocket.Conn, channelID string, connectURL *string) error {
	keepaliveTimeout := 30 * time.Second // Default, updated from welcome message

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(keepaliveTimeout + 10*time.Second))
		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}

		// Parse the EventSub message
		var msg struct {
			Metadata struct {
				MessageType string `json:"message_type"`
			} `json:"metadata"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("[TEMP DEBUG][SharedChat] Error parsing EventSub message: %v", err)
			continue
		}

		switch msg.Metadata.MessageType {
		case "session_welcome":
			var payload struct {
				Session struct {
					ID                      string `json:"id"`
					KeepaliveTimeoutSeconds int    `json:"keepalive_timeout_seconds"`
				} `json:"session"`
			}
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				return fmt.Errorf("error parsing welcome: %w", err)
			}

			esc.SessionID = payload.Session.ID
			if payload.Session.KeepaliveTimeoutSeconds > 0 {
				keepaliveTimeout = time.Duration(payload.Session.KeepaliveTimeoutSeconds) * time.Second
			}

			log.Printf("[TEMP DEBUG][SharedChat] EventSub welcome for %s, session=%s, keepalive=%ds",
				channelID, esc.SessionID, payload.Session.KeepaliveTimeoutSeconds)

			// Create subscriptions
			if err := createSharedChatSubscriptions(channelID, esc.SessionID); err != nil {
				return fmt.Errorf("error creating subscriptions: %w", err)
			}

		case "session_keepalive":
			// Just reset the deadline, already handled by SetReadDeadline
			continue

		case "session_reconnect":
			var payload struct {
				Session struct {
					ReconnectURL string `json:"reconnect_url"`
				} `json:"session"`
			}
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("[TEMP DEBUG][SharedChat] Error parsing reconnect: %v", err)
				continue
			}
			log.Printf("[TEMP DEBUG][SharedChat] EventSub reconnect for %s to %s", channelID, payload.Session.ReconnectURL)
			*connectURL = payload.Session.ReconnectURL
			return nil // Return to trigger reconnection with new URL

		case "notification":
			handleEventSubNotification(esc, msg.Payload)

		case "revocation":
			log.Printf("[TEMP DEBUG][SharedChat] EventSub subscription revoked for %s", channelID)
		}
	}
}

// createSharedChatSubscriptions creates the three shared chat EventSub subscriptions
func createSharedChatSubscriptions(channelID, sessionID string) error {
	subTypes := []string{
		"channel.shared_chat.begin",
		"channel.shared_chat.update",
		"channel.shared_chat.end",
	}

	for _, subType := range subTypes {
		body := map[string]interface{}{
			"type":    subType,
			"version": "1",
			"condition": map[string]string{
				"broadcaster_user_id": channelID,
			},
			"transport": map[string]string{
				"method":     "websocket",
				"session_id": sessionID,
			},
		}

		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("error marshaling subscription body: %w", err)
		}

		req, err := http.NewRequest("POST", "https://api.twitch.tv/helix/eventsub/subscriptions", bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("error creating subscription request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Client-Id", clientID)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("error sending subscription request: %w", err)
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			log.Printf("[TEMP DEBUG][SharedChat] Token expired, refreshing...")
			if err := refreshTokenOnce(); err != nil {
				return fmt.Errorf("error refreshing token: %w", err)
			}
			// Retry the subscription
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("error retrying subscription: %w", err)
			}
			respBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}

		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			log.Printf("[TEMP DEBUG][SharedChat] Subscription %s failed (%d): %s", subType, resp.StatusCode, string(respBody))
		} else {
			log.Printf("[TEMP DEBUG][SharedChat] Subscription %s created for channel %s", subType, channelID)
		}
	}

	return nil
}

// handleEventSubNotification processes a notification from EventSub
func handleEventSubNotification(esc *EventSubChannel, payload json.RawMessage) {
	var notif struct {
		Subscription struct {
			Type string `json:"type"`
		} `json:"subscription"`
		Event json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(payload, &notif); err != nil {
		log.Printf("[TEMP DEBUG][SharedChat] Error parsing notification: %v", err)
		return
	}

	log.Printf("[TEMP DEBUG][SharedChat] Received event: %s for channel %s", notif.Subscription.Type, esc.ChannelID)

	var eventData struct {
		SessionID               string                `json:"session_id"`
		BroadcasterUserID       string                `json:"broadcaster_user_id"`
		BroadcasterUserLogin    string                `json:"broadcaster_user_login"`
		HostBroadcasterUserID   string                `json:"host_broadcaster_user_id"`
		HostBroadcasterUserLogin string               `json:"host_broadcaster_user_login"`
		Participants             []SharedChatParticipant `json:"participants"`
	}
	if err := json.Unmarshal(notif.Event, &eventData); err != nil {
		log.Printf("[TEMP DEBUG][SharedChat] Error parsing event data: %v", err)
		return
	}

	var eventType string
	switch notif.Subscription.Type {
	case "channel.shared_chat.begin":
		eventType = "begin"
	case "channel.shared_chat.update":
		eventType = "update"
	case "channel.shared_chat.end":
		eventType = "end"
	default:
		log.Printf("[TEMP DEBUG][SharedChat] Unknown event type: %s", notif.Subscription.Type)
		return
	}

	event := SharedChatEvent{
		Type:         eventType,
		SessionID:    eventData.SessionID,
		HostID:       eventData.HostBroadcasterUserID,
		HostLogin:    eventData.HostBroadcasterUserLogin,
		Participants: eventData.Participants,
	}

	log.Printf("[TEMP DEBUG][SharedChat] Event %s: session=%s, host=%s, participants=%d",
		eventType, eventData.SessionID, eventData.HostBroadcasterUserLogin, len(eventData.Participants))

	broadcastToSSEClients(esc, event)
}

// stopEventSubForChannel stops the EventSub WS for a channel
func stopEventSubForChannel(channelID string) {
	eventSubMutex.RLock()
	esc, exists := eventSubChannels[channelID]
	eventSubMutex.RUnlock()

	if !exists {
		return
	}

	log.Printf("[TEMP DEBUG][SharedChat] Stopping EventSub for channel %s", channelID)
	esc.Cancel()
	if esc.Conn != nil {
		esc.Conn.Close()
	}
}

func main() {
	// cacheBuster("./src/index.html")
	// cacheBuster("./src/v2/index.html")
	// load access and refresh tokens from file
	file, err := os.Open("tokens.json")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()

	var tokens map[string]string
	err = json.NewDecoder(file).Decode(&tokens)
	if err != nil {
		log.Fatal(err)
		return
	}
	accessToken = tokens["access_token"]
	refreshToken = tokens["refresh_token"]
	clientID = tokens["client_id"]
	clientSecret = tokens["client_secret"]
	if accessToken == "" {
		log.Fatal("No access token found.")
		return
	}
	if refreshToken == "" {
		log.Fatal("No refresh token found.")
		return
	}
	if clientID == "" {
		log.Fatal("No client ID found.")
		return
	}
	if clientSecret == "" {
		log.Fatal("No client secret found.")
		return
	}
	log.Println("Access token: " + accessToken)

	args := os.Args[1:]
	port := args[0]
	var location string
	if len(args) > 1 {
		location = args[1]
		if location == "" {
			location = "remote"
		}
	} else {
		location = "remote"
	}
	var callbackUrl string
	if location == "local" {
		callbackUrl = "http://localhost" + port + "/auth/callback"
	} else {
		callbackUrl = "https://chat.johnnycyan.com/auth/callback"
	}

	client, err = helix.NewClient(&helix.Options{
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		RedirectURI:     callbackUrl,
		UserAccessToken: accessToken,
		RefreshToken:    refreshToken,
	})
	if err != nil {
		log.Println(err)
	}
	client.OnUserAccessTokenRefreshed(func(newAccessToken, newRefreshToken string) {
		log.Println("Refreshed access token")
		accessToken = newAccessToken
		refreshToken = newRefreshToken
		saveTokens(accessToken, refreshToken)
		client.SetUserAccessToken(accessToken)
		client.SetRefreshToken(refreshToken)
	})
	go refreshTokenLoop()
	url := client.GetAuthorizationURL(&helix.AuthorizationURLParams{
		ResponseType: "code", // or "token"
		Scopes:       []string{},
		State:        "some-state",
		ForceVerify:  false,
	})
	log.Printf("%s\n", url)

	http.HandleFunc("/twitch/oauth", TwitchOAuthHandler)
	http.HandleFunc("/twitch/api", TwitchAPIHandler)
	http.HandleFunc("/auth/callback", TwitchRedirectHandler)
	http.HandleFunc("/twitch/get_id", TwitchGetUserIDforUsernameHandler)
	http.HandleFunc("/api/chatterino-badges", handleChatterinoBadges)
	http.HandleFunc("/api/tts", synthesizeSpeechHandler)
	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/active", handleActive)
	http.HandleFunc("/admin/active", handleAdminActive)
	http.HandleFunc("/api/shared-chat/subscribe", handleSharedChatSubscribe)
	http.HandleFunc("/api/shared-chat/events", handleSharedChatEvents)
	// serve the current directory as a static web server
	staticFilesV2 := http.FileServer(http.Dir("./dist"))
	http.Handle("/", staticFilesV2)

	log.Println("Serving static files from current directory on http://localhost" + port)
	err = http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
