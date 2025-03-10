package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	log "github.com/sirupsen/logrus"
)

// NWCMethod is the "method" in NWC requests
type NWCMethod string

// Some NWC methods:
const (
	MethodGetInfo          NWCMethod = "get_info"
	MethodPayInvoice       NWCMethod = "pay_invoice"
	MethodMakeInvoice      NWCMethod = "make_invoice"
	MethodLookupInvoice    NWCMethod = "lookup_invoice"
	MethodListTransactions NWCMethod = "list_transactions"
	MethodGetBalance       NWCMethod = "get_balance"
	MethodMakeChainAddress NWCMethod = "make_chain_address"
)

// NWCRequest basic structure.
type NWCRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

// Generic response structure for NWC
type NWCResponse struct {
	ResultType string          `json:"result_type"`
	Error      *NWCError       `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
}

// NWCError represents an error in the response
type NWCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response-specific result structures
type GetInfoResult struct {
	Alias         string   `json:"alias"`
	Color         string   `json:"color,omitempty"`
	Pubkey        string   `json:"pubkey,omitempty"`
	Network       string   `json:"network,omitempty"`
	BlockHeight   int      `json:"block_height,omitempty"`
	BlockHash     string   `json:"block_hash,omitempty"`
	Methods       []string `json:"methods"`
	Notifications []string `json:"notifications,omitempty"`
}

type PayInvoiceResult struct {
	Preimage string `json:"preimage"`
	FeesPaid int64  `json:"fees_paid,omitempty"`
}

type MakeInvoiceResult struct {
	Type            string      `json:"type"`
	Invoice         string      `json:"invoice,omitempty"`
	Description     string      `json:"description,omitempty"`
	DescriptionHash string      `json:"description_hash,omitempty"`
	Preimage        string      `json:"preimage,omitempty"`
	PaymentHash     string      `json:"payment_hash"`
	Amount          int64       `json:"amount"`
	FeesPaid        int64       `json:"fees_paid,omitempty"`
	CreatedAt       int64       `json:"created_at"`
	ExpiresAt       int64       `json:"expires_at,omitempty"`
	Metadata        interface{} `json:"metadata,omitempty"`
}

type GetBalanceResult struct {
	Balance int64 `json:"balance"`
}

type Transaction struct {
	Type            string      `json:"type"`
	Invoice         string      `json:"invoice,omitempty"`
	Description     string      `json:"description,omitempty"`
	DescriptionHash string      `json:"description_hash,omitempty"`
	Preimage        string      `json:"preimage,omitempty"`
	PaymentHash     string      `json:"payment_hash"`
	Amount          int64       `json:"amount"`
	FeesPaid        int64       `json:"fees_paid,omitempty"`
	CreatedAt       int64       `json:"created_at"`
	ExpiresAt       int64       `json:"expires_at,omitempty"`
	SettledAt       int64       `json:"settled_at,omitempty"`
	Metadata        interface{} `json:"metadata,omitempty"`
}

type ListTransactionsResult struct {
	Transactions []Transaction `json:"transactions"`
}

// Style definitions
var (
	// Colors
	accentColor    = lipgloss.Color("#FFBF00") // Gold
	secondaryColor = lipgloss.Color("#6699CC") // Blue
	successColor   = lipgloss.Color("#28A745") // Green
	errorColor     = lipgloss.Color("#DC3545") // Red
	warningColor   = lipgloss.Color("#FFC107") // Amber
	infoColor      = lipgloss.Color("#17A2B8") // Cyan
	mutedColor     = lipgloss.Color("#869099") // Gray

	// Styles
	titleStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true)

	labelStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Width(15).
			Align(lipgloss.Right)

	valueStyle = lipgloss.NewStyle().
			PaddingLeft(1)

	successStyle = lipgloss.NewStyle().
			Foreground(successColor).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true)

	highlightStyle = lipgloss.NewStyle().
			Foreground(accentColor)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accentColor).
			Padding(1).
			MarginTop(1).
			MarginBottom(1)
)

func main() {
	// Command-line flag for log level
	logLevel := flag.String("loglevel", "info", "Set log level (debug, info, warn, error)")
	flag.Parse()

	// Set log level based on the flag
	switch *logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	fmt.Println(titleStyle.Render("=== Nostr Wallet Connect (NWC) Demo ==="))

	// 1. Read NWC connection string from the user:
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(labelStyle.Render("NWC URL") + valueStyle.Render("Enter NWC connection string (e.g. nostr+walletconnect://...): "))
	connStr, _ := reader.ReadString('\n')
	connStr = strings.TrimSpace(connStr)

	log.WithField("connStr", connStr).Debug("Parsing NWC connection string")

	parsed, err := parseNWCConnectionString(connStr)
	if err != nil {
		log.WithError(err).Error("Error parsing NWC string")
		fmt.Println(errorStyle.Render("Error: ") + err.Error())
		return
	}
	log.WithFields(log.Fields{
		"walletPubKey": parsed.WalletPubKey,
		"relay":        parsed.Relay,
		"secretLen":    len(parsed.WalletSecret),
	}).Debug("Successfully parsed NWC connection string")

	// 2. We'll set up an ephemeral key pair for this client
	clientSecretKey := nostr.GeneratePrivateKey()
	clientPubKey, err := nostr.GetPublicKey(clientSecretKey)
	if err != nil {
		log.WithError(err).Error("Could not derive pubkey")
		fmt.Println(errorStyle.Render("Error: Could not derive pubkey"))
		return
	}
	log.WithField("clientPubKey", clientPubKey).Info("Generated client ephemeral keypair")

	fmt.Println(successStyle.Render("✓ ") + "Connected with client key: " + highlightStyle.Render(clientPubKey))

	// 3. Use go-nostr's SimplePool to connect to the provided relay
	ctx := context.Background()
	pool := nostr.NewSimplePool(ctx)
	since := nostr.Timestamp(time.Now().Unix())

	// Subscribe to responses from the wallet
	// The wallet should send events with kind=24134 (KindNWCWalletResponse)
	// tagged with p=<clientPubKey> and e=<requestID>.
	log.WithFields(log.Fields{
		"relay":    parsed.Relay,
		"clientPK": clientPubKey,
		"since":    since,
	}).Debug("Setting up subscription for responses")

	filters := nostr.Filter{
		Kinds: []int{nostr.KindNWCWalletResponse}, // 24134
		Tags:  nostr.TagMap{"p": []string{clientPubKey}},
		Since: &since,
	}
	sub := pool.SubscribeMany(ctx, []string{parsed.Relay}, filters)

	// We'll handle responses in a goroutine
	responses := make(chan nostr.Event, 10)

	go func() {
		log.Debug("Starting response handling goroutine")
		for evt := range sub {
			if evt.Event == nil {
				log.Debug("Received nil event from subscription")
				continue
			}

			// Log more details about incoming responses
			log.WithFields(log.Fields{
				"eventID": evt.Event.ID,
				"kind":    evt.Event.Kind,
				"pubkey":  evt.Event.PubKey,
				"content": evt.Event.Content,
				"tags":    evt.Event.Tags,
			}).Debug("Received response event")

			responses <- *evt.Event
		}
	}()

	// 4. Send a get_info request
	fmt.Println(subtitleStyle.Render("\nSending get_info request to wallet..."))
	err = sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodGetInfo, nil)
	if err != nil {
		log.WithError(err).Error("Error sending get_info request")
		fmt.Println(errorStyle.Render("Error: ") + err.Error())
	} else {
		// Wait for the response (we only do a quick wait here)
		select {
		case resp := <-responses:
			log.WithField("eventID", resp.ID).Debug("Got response for get_info")
			decrypted, err := decryptResponseContent(resp, clientSecretKey, parsed.WalletPubKey)
			if err != nil {
				log.WithError(err).Error("Failed to decrypt response")
				fmt.Println(errorStyle.Render("Error: ") + "Failed to decrypt response: " + err.Error())
			} else {
				log.WithField("decrypted", decrypted).Debug("Decrypted get_info response")
				log.WithField("decryptedContent", decrypted).Debug("Decrypted content for unmarshalling")

				// Parse and display the response
				displayParsedResponse(decrypted)
			}

		case <-time.After(5 * time.Second):
			log.Warn("Timed out waiting for get_info response")
			fmt.Println(errorStyle.Render("Timed out waiting for get_info response."))
		}
	}

	// 5. Drop into an interactive command loop for the user
	fmt.Println(boxStyle.Render(fmt.Sprintf(`%s
   make_invoice <amount_msat> <description> [<expiry_seconds>]
   pay_invoice <lightning_invoice_string>
   get_balance
   list_transactions
   make_chain_address
   exit`, titleStyle.Render("Available commands:"))))

	for {
		fmt.Print(highlightStyle.Render("nwc> "))
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}
		if line == "exit" {
			log.Info("Exiting application")
			fmt.Println(subtitleStyle.Render("Exiting..."))
			break
		}

		cmdParts := strings.Split(line, " ")
		log.WithField("command", cmdParts[0]).Info("Processing command")
		switch cmdParts[0] {
		case "make_invoice":
			if len(cmdParts) < 3 {
				fmt.Println(errorStyle.Render("Usage: make_invoice <amount_msat> <description> [<expiry_seconds>]"))
				continue
			}
			amount := cmdParts[1]
			desc := cmdParts[2]
			expiry := "3600" // default
			if len(cmdParts) > 3 {
				expiry = cmdParts[3]
			}
			params := map[string]interface{}{
				"amount":      parseInt(amount),
				"description": desc,
				"expiry":      parseInt(expiry),
			}
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodMakeInvoice, params)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send make_invoice request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "pay_invoice":
			if len(cmdParts) < 2 {
				fmt.Println(errorStyle.Render("Usage: pay_invoice <invoice_string>"))
				continue
			}
			invoice := cmdParts[1]
			params := map[string]interface{}{
				"invoice": invoice,
			}
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodPayInvoice, params)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send pay_invoice request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "get_balance":
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodGetBalance, nil)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send get_balance request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "list_transactions":
			// you can add optional from/until/limit etc. For simplicity, send empty.
			params := map[string]interface{}{}
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodListTransactions, params)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send list_transactions request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "make_chain_address":
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodMakeChainAddress, nil)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send make_chain_address request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		default:
			fmt.Println(errorStyle.Render("Unrecognized command. Try: make_invoice, pay_invoice, get_balance, list_transactions, make_chain_address, exit"))
		}
	}
}

// Step A: parse NWC connection string of form:
//
//	nostr+walletconnect://<pubkey>?relay=<relayURL>&secret=<secretKey>
type nwcParsed struct {
	WalletPubKey string
	Relay        string
	WalletSecret string
}

func parseNWCConnectionString(nwc string) (*nwcParsed, error) {
	log.WithField("nwc", nwc).Debug("Parsing NWC connection string")

	if !strings.HasPrefix(nwc, "nostr+walletconnect://") {
		return nil, fmt.Errorf("invalid format: must start with nostr+walletconnect://")
	}
	stripped := strings.TrimPrefix(nwc, "nostr+walletconnect://")

	parts := strings.Split(stripped, "?")
	if len(parts) != 2 {
		log.Error("Invalid format: missing query parameters")
		return nil, fmt.Errorf("invalid format: missing ?relay=..., &secret=...")
	}
	pubkey := parts[0]
	log.WithField("pubkey", pubkey).Debug("Found wallet pubkey")

	var relay, secret string

	query := parts[1]
	for _, kv := range strings.Split(query, "&") {
		p := strings.SplitN(kv, "=", 2)
		if len(p) < 2 {
			continue
		}
		key := p[0]
		val := p[1]
		if key == "relay" {
			// Decode the relay URL
			decodedRelay, err := url.QueryUnescape(val)
			if err != nil {
				log.WithError(err).Error("Failed to decode relay URL")
				return nil, fmt.Errorf("failed to decode relay URL: %w", err)
			}
			relay = decodedRelay
			log.WithField("relay", relay).Debug("Found relay")
		} else if key == "secret" {
			secret = val
			log.Debug("Found secret")
		}
	}
	if relay == "" || secret == "" {
		log.Error("Missing relay or secret parameter")
		return nil, fmt.Errorf("invalid format: missing relay or secret param")
	}

	return &nwcParsed{
		WalletPubKey: pubkey,
		Relay:        strings.TrimSpace(relay),
		WalletSecret: strings.TrimSpace(secret),
	}, nil
}

// Step B: Actually build and publish an NWC request event
func sendNWCRequest(
	ctx context.Context,
	pool *nostr.SimplePool,
	nwc *nwcParsed,
	clientSecKey, clientPubKey string,
	method NWCMethod,
	params interface{},
) error {
	log.WithFields(log.Fields{
		"method":       method,
		"relay":        nwc.Relay,
		"clientPubKey": clientPubKey,
		"walletPubKey": nwc.WalletPubKey,
	}).Debug("Preparing to send NWC request")

	// Our request object
	req := NWCRequest{
		Method: string(method),
		Params: params,
	}
	bytesReq, err := json.Marshal(req)
	if err != nil {
		log.WithError(err).Error("Failed to marshal request")
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	log.WithField("request", string(bytesReq)).Debug("Marshalled request")

	// We must do NIP04 encryption with the wallet's pubkey using our ephemeral private key
	log.Debug("Computing shared secret")
	sharedSecret, err := nip04.ComputeSharedSecret(nwc.WalletPubKey, clientSecKey)
	if err != nil {
		log.WithError(err).Error("Failed to compute shared secret")
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}
	log.Debug("Successfully computed shared secret")

	log.Debug("Encrypting request content")
	encryptedContent, err := nip04.Encrypt(string(bytesReq), sharedSecret)
	if err != nil {
		log.WithError(err).Error("Failed to nip04-encrypt request")
		return fmt.Errorf("failed to nip04-encrypt request: %w", err)
	}
	log.WithField("encryptedLength", len(encryptedContent)).Debug("Successfully encrypted content")

	// According to the NWC spec:
	//   * "request" events use kind=24133 (NWCWalletRequest)
	//   * 'p' tag set to the wallet's pubkey
	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    clientPubKey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags: nostr.Tags{
			nostr.Tag{"p", nwc.WalletPubKey},
		},
	}
	// Sign with the ephemeral key
	log.Debug("Signing event with client key")
	event.Sign(clientSecKey)
	log.WithFields(log.Fields{
		"signature": event.Sig,
		"eventID":   event.ID,
	}).Debug("Event signed")

	// Check if the event is valid before publishing
	ok, err := event.CheckSignature()
	if err != nil || !ok {
		log.WithError(err).WithField("valid", ok).Error("Event signature validation failed")
		return fmt.Errorf("event signature validation failed: %v, %w", ok, err)
	}
	log.Debug("Event signature validated successfully")

	// Publish to the wallet's relay
	log.WithFields(log.Fields{
		"relay":   nwc.Relay,
		"eventID": event.ID,
	}).Debug("Publishing event to relay")

	status := pool.PublishMany(ctx, []string{nwc.Relay}, event)

	if stat := <-status; stat.Error != nil {
		log.WithFields(log.Fields{
			"relay": stat.Relay,
			"error": stat.Error.Error(),
		}).Error("Failed to publish to relay")
		return fmt.Errorf("failed to publish event to %s: %w", nwc.Relay, stat.Error)
	} else {
		log.WithFields(log.Fields{
			"relay":  stat.Relay,
			"status": "ok",
		}).Info("Successfully published to relay")
	}

	log.WithFields(log.Fields{
		"method":  method,
		"eventID": event.ID,
	}).Info("Sent request successfully")

	fmt.Println(successStyle.Render("✓ ") + "Sent request: " + string(method) + " (Event ID: " + highlightStyle.Render(event.ID) + ")")
	return nil
}

// waitForPrettyResponse waits for a response and displays it prettily
func waitForPrettyResponse(
	responses chan nostr.Event,
	clientSecKey string,
	walletPubKey string,
) {
	fmt.Println(subtitleStyle.Render("Waiting for response..."))
	select {
	case resp := <-responses:
		log.WithFields(log.Fields{
			"eventID": resp.ID,
			"pubkey":  resp.PubKey,
		}).Debug("Received response event")

		decrypted, err := decryptResponseContent(resp, clientSecKey, walletPubKey)
		if err != nil {
			log.WithError(err).Error("Error decrypting response")
			fmt.Println(errorStyle.Render("Error: ") + "Failed to decrypt response: " + err.Error())
		} else {
			log.WithField("content", decrypted).Debug("Successfully decrypted response")
			fmt.Println(subtitleStyle.Render("Response received (Event ID: ") + highlightStyle.Render(resp.ID) + subtitleStyle.Render(")"))

			// Parse and display the response in a pretty way
			displayParsedResponse(decrypted)
		}
	case <-time.After(10 * time.Second):
		log.Warn("Timed out waiting for response")
		fmt.Println(errorStyle.Render("Timed out waiting for response."))
	}
}

// Decrypt the content from the wallet. The wallet's `PubKey` in the event
// is the NWC wallet's pubkey. The event's `Content` is NIP-04 encrypted to us.
func decryptResponseContent(ev nostr.Event, clientSecKey, walletPubKey string) (string, error) {
	// Extract e tags for debugging
	var referencedEvents []string
	for _, tag := range ev.Tags {
		if tag[0] == "e" && len(tag) > 1 {
			referencedEvents = append(referencedEvents, tag[1])
		}
	}

	log.WithFields(log.Fields{
		"eventID":          ev.ID,
		"eventPubKey":      ev.PubKey,
		"walletPubKey":     walletPubKey,
		"referencedEvents": referencedEvents,
	}).Debug("Attempting to decrypt response content")

	// Check if the pubkey matches what we expect
	if ev.PubKey != walletPubKey {
		log.WithFields(log.Fields{
			"expectedPubKey": walletPubKey,
			"actualPubKey":   ev.PubKey,
		}).Warn("Response pubkey doesn't match wallet pubkey")
		// Continue anyway, as some wallets might use different keys
	}

	sharedSecret, err := nip04.ComputeSharedSecret(ev.PubKey, clientSecKey)
	if err != nil {
		log.WithError(err).Error("Failed to compute shared secret for decryption")
		return "", err
	}
	log.Debug("Computed shared secret for decryption")

	decrypted, err := nip04.Decrypt(ev.Content, sharedSecret)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt content")
		return "", err
	}
	log.Debug("Successfully decrypted content")

	return decrypted, nil
}

// Parse and display the response in a pretty way
func displayParsedResponse(jsonStr string) {
	var resp NWCResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	if err != nil {
		log.WithError(err).Error("Failed to parse response")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse response: " + err.Error())
		return
	}

	// Check for error first
	if resp.Error != nil {
		fmt.Println(errorStyle.Render("Error: ") + resp.Error.Code + " - " + resp.Error.Message)
		return
	}

	// Process by result type
	switch resp.ResultType {
	case "get_info":
		displayGetInfoResult(resp.Result)
	case "pay_invoice":
		displayPayInvoiceResult(resp.Result)
	case "make_invoice":
		displayMakeInvoiceResult(resp.Result)
	case "lookup_invoice":
		displayMakeInvoiceResult(resp.Result) // Same structure as make_invoice
	case "get_balance":
		displayGetBalanceResult(resp.Result)
	case "list_transactions":
		displayListTransactionsResult(resp.Result)
	default:
		// For any other result type, just pretty print the JSON
		var prettyJSON map[string]interface{}
		json.Unmarshal(resp.Result, &prettyJSON)
		jsonBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")

		fmt.Println(boxStyle.Render(highlightStyle.Render("Result Type: ") + resp.ResultType + "\n\n" + string(jsonBytes)))
	}
}

// Display functions for each result type

func displayGetInfoResult(resultJson json.RawMessage) {
	var result GetInfoResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse get_info result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse get_info result: " + err.Error())
		return
	}

	content := fmt.Sprintf(`%s %s

%s %s
%s %s
%s %s
%s %s
%s %d

%s 
%s

%s 
%s`,
		subtitleStyle.Render("Wallet Info:"),
		valueStyle.Render(result.Alias),

		labelStyle.Render("Network:"),
		valueStyle.Render(result.Network),
		labelStyle.Render("Pubkey:"),
		valueStyle.Render(result.Pubkey),
		labelStyle.Render("Color:"),
		valueStyle.Render(result.Color),
		labelStyle.Render("Block Hash:"),
		valueStyle.Render(result.BlockHash),
		labelStyle.Render("Block Height:"),
		result.BlockHeight,

		subtitleStyle.Render("Supported Methods:"),
		valueStyle.Render(strings.Join(result.Methods, ", ")),

		subtitleStyle.Render("Notifications:"),
		valueStyle.Render(strings.Join(result.Notifications, ", ")),
	)

	fmt.Println(boxStyle.Render(content))
}

func displayPayInvoiceResult(resultJson json.RawMessage) {
	var result PayInvoiceResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse pay_invoice result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse pay_invoice result: " + err.Error())
		return
	}

	content := fmt.Sprintf(`%s

%s %s
%s %d sats`,
		successStyle.Render("Payment Successful!"),

		labelStyle.Render("Preimage:"),
		valueStyle.Render(result.Preimage),
		labelStyle.Render("Fees Paid:"),
		result.FeesPaid/1000,
	)

	fmt.Println(boxStyle.Render(content))
}

func displayMakeInvoiceResult(resultJson json.RawMessage) {
	var result MakeInvoiceResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse invoice result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse invoice result: " + err.Error())
		return
	}

	// Format timestamps
	created := time.Unix(result.CreatedAt, 0).Format("2006-01-02 15:04:05")
	expires := ""
	if result.ExpiresAt > 0 {
		expires = time.Unix(result.ExpiresAt, 0).Format("2006-01-02 15:04:05")
	}

	content := fmt.Sprintf(`%s

%s %s
%s %s
%s %d sats (%d msats)
%s %s 
%s %s
%s %s`,
		subtitleStyle.Render("Invoice Details"),

		labelStyle.Render("Type:"),
		valueStyle.Render(result.Type),
		labelStyle.Render("Description:"),
		valueStyle.Render(result.Description),
		labelStyle.Render("Amount:"),
		result.Amount/1000, result.Amount,
		labelStyle.Render("Payment Hash:"),
		valueStyle.Render(result.PaymentHash),
		labelStyle.Render("Created:"),
		valueStyle.Render(created),
		labelStyle.Render("Expires:"),
		valueStyle.Render(expires),
	)

	// Add the actual invoice at the bottom in a highlighted box
	if result.Invoice != "" {
		invoiceBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(successColor).
			Padding(1).
			Align(lipgloss.Center).
			Render(result.Invoice)

		content = content + "\n\n" + invoiceBox
	}

	fmt.Println(boxStyle.Render(content))
}

func displayGetBalanceResult(resultJson json.RawMessage) {
	var result GetBalanceResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse get_balance result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse get_balance result: " + err.Error())
		return
	}

	// Format balance in both sats and msats
	balanceSats := float64(result.Balance) / 1000.0

	content := fmt.Sprintf(`%s

%s %s
%s %.3f sats
%s %d msats`,
		subtitleStyle.Render("Wallet Balance"),

		labelStyle.Render("Status:"),
		successStyle.Render("AVAILABLE"),
		labelStyle.Render("Balance:"),
		balanceSats,
		labelStyle.Render("Balance (msats):"),
		result.Balance,
	)

	fmt.Println(boxStyle.Render(content))
}

func displayListTransactionsResult(resultJson json.RawMessage) {
	var result ListTransactionsResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse list_transactions result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse list_transactions result: " + err.Error())
		return
	}

	if len(result.Transactions) == 0 {
		fmt.Println(boxStyle.Render(subtitleStyle.Render("Transactions") + "\n\nNo transactions found."))
		return
	}

	// Create a header
	transactionsList := subtitleStyle.Render("Recent Transactions") + "\n\n"

	// Add divider line
	divider := strings.Repeat("─", 50) + "\n"
	transactionsList += divider

	// Add each transaction
	for i, tx := range result.Transactions {
		// Format timestamps
		created := time.Unix(tx.CreatedAt, 0).Format("2006-01-02 15:04:05")
		settled := ""
		if tx.SettledAt > 0 {
			settled = time.Unix(tx.SettledAt, 0).Format("2006-01-02 15:04:05")
		}

		// Pick color based on type
		typeColor := successColor
		if tx.Type == "outgoing" {
			typeColor = warningColor
		}

		txType := lipgloss.NewStyle().Foreground(typeColor).Bold(true).Render(tx.Type)
		amountStr := fmt.Sprintf("%d sats", tx.Amount/1000)
		if tx.Type == "outgoing" {
			amountStr = "-" + amountStr
		} else {
			amountStr = "+" + amountStr
		}
		amountStyle := lipgloss.NewStyle().Foreground(typeColor).Bold(true).Render(amountStr)

		// Format the payment hash safely
		paymentHashDisplay := "N/A"
		if len(tx.PaymentHash) > 0 {
			if len(tx.PaymentHash) > 16 {
				paymentHashDisplay = tx.PaymentHash[:16] + "..."
			} else {
				paymentHashDisplay = tx.PaymentHash
			}
		}

		txContent := fmt.Sprintf(`%s %s   %s

%s %s
%s %s
%s %s
%s %s`,
			txType,
			created,
			amountStyle,

			labelStyle.Render("Description:"),
			valueStyle.Render(tx.Description),
			labelStyle.Render("Payment Hash:"),
			valueStyle.Render(paymentHashDisplay),
			labelStyle.Render("Created:"),
			valueStyle.Render(created),
			labelStyle.Render("Settled:"),
			valueStyle.Render(settled),
		)

		transactionsList += txContent + "\n"

		// Add divider between transactions
		if i < len(result.Transactions)-1 {
			transactionsList += divider
		}
	}

	fmt.Println(boxStyle.Render(transactionsList))
}

// Helper for command parsing
func parseInt(s string) int64 {
	var val int64
	fmt.Sscanf(s, "%d", &val)
	log.WithFields(log.Fields{
		"input":  s,
		"parsed": val,
	}).Debug("Parsed integer")
	return val
}
