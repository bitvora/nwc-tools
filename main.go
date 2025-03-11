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

type NWCMethod string

const (
	MethodGetInfo               NWCMethod = "get_info"
	MethodPayInvoice            NWCMethod = "pay_invoice"
	MethodMakeInvoice           NWCMethod = "make_invoice"
	MethodLookupInvoice         NWCMethod = "lookup_invoice"
	MethodListTransactions      NWCMethod = "list_transactions"
	MethodGetBalance            NWCMethod = "get_balance"
	MethodMakeChainAddress      NWCMethod = "make_chain_address"
	MethodListChainTransactions NWCMethod = "list_chain_transactions"
	MethodPayChainAddress       NWCMethod = "pay_chain_address"
)

type NWCRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

type NWCResponse struct {
	ResultType string          `json:"result_type"`
	Error      *NWCError       `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
}

type NWCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

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

type ChainTransaction struct {
	Type          string      `json:"type"`
	TxID          string      `json:"txid"`
	Amount        int64       `json:"amount"`
	Confirmations int         `json:"confirmations"`
	Metadata      interface{} `json:"metadata,omitempty"`
	Address       string      `json:"address,omitempty"`
}

type ListChainTransactionsResult struct {
	Transactions []ChainTransaction `json:"transactions"`
}

type PayChainAddressResult struct {
	TxID string `json:"txid"`
}

var (
	accentColor    = lipgloss.Color("#FFBF00")
	secondaryColor = lipgloss.Color("#6699CC")
	successColor   = lipgloss.Color("#28A745")
	errorColor     = lipgloss.Color("#DC3545")
	warningColor   = lipgloss.Color("#FFC107")
	infoColor      = lipgloss.Color("#17A2B8")
	mutedColor     = lipgloss.Color("#869099")

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
	logLevel := flag.String("loglevel", "debug", "Set log level (debug, info, warn, error)")
	flag.Parse()

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

	clientSecretKey := nostr.GeneratePrivateKey()
	clientPubKey, err := nostr.GetPublicKey(clientSecretKey)
	if err != nil {
		log.WithError(err).Error("Could not derive pubkey")
		fmt.Println(errorStyle.Render("Error: Could not derive pubkey"))
		return
	}
	log.WithField("clientPubKey", clientPubKey).Info("Generated client ephemeral keypair")

	fmt.Println(successStyle.Render("✓ ") + "Connected with client key: " + highlightStyle.Render(clientPubKey))

	ctx := context.Background()
	pool := nostr.NewSimplePool(ctx)
	since := nostr.Timestamp(time.Now().Unix())

	log.WithFields(log.Fields{
		"relay":    parsed.Relay,
		"clientPK": clientPubKey,
		"since":    since,
	}).Debug("Setting up subscription for responses")

	filters := nostr.Filter{
		Kinds: []int{nostr.KindNWCWalletResponse},
		Tags:  nostr.TagMap{"p": []string{clientPubKey}},
		Since: &since,
	}
	sub := pool.SubscribeMany(ctx, []string{parsed.Relay}, filters)

	responses := make(chan nostr.Event, 10)

	go func() {
		log.Debug("Starting response handling goroutine")
		for evt := range sub {
			if evt.Event == nil {
				log.Debug("Received nil event from subscription")
				continue
			}

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

	fmt.Println(subtitleStyle.Render("\nSending get_info request to wallet..."))
	err = sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodGetInfo, nil)
	if err != nil {
		log.WithError(err).Error("Error sending get_info request")
		fmt.Println(errorStyle.Render("Error: ") + err.Error())
	} else {
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

				displayParsedResponse(decrypted)
			}

		case <-time.After(5 * time.Second):
			log.Warn("Timed out waiting for get_info response")
			fmt.Println(errorStyle.Render("Timed out waiting for get_info response."))
		}
	}

	fmt.Println(boxStyle.Render(fmt.Sprintf(`%s
   make_invoice <amount_msat> <description> [<expiry_seconds>]
   pay_invoice <lightning_invoice_string>
   get_balance
   list_transactions
   list_chain_transactions [limit] [from_timestamp] [until_timestamp] [offset]
   make_chain_address
   pay_chain_address <address> <amount>
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
			expiry := "3600"
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
			params := map[string]interface{}{}
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodListTransactions, params)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send list_transactions request: " + err.Error())
				continue
			}

			// Add debug logging to confirm the request was sent
			log.Info("list_transactions request sent, waiting for response...")

			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "list_chain_transactions":
			params := map[string]interface{}{}

			// Parse optional parameters
			if len(cmdParts) > 1 {
				limit := parseInt(cmdParts[1])
				params["limit"] = limit
			}
			if len(cmdParts) > 2 {
				from := parseInt(cmdParts[2])
				params["from"] = from
			}
			if len(cmdParts) > 3 {
				until := parseInt(cmdParts[3])
				params["until"] = until
			}
			if len(cmdParts) > 4 {
				offset := parseInt(cmdParts[4])
				params["offset"] = offset
			}

			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodListChainTransactions, params)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send list_chain_transactions request: " + err.Error())
				continue
			}

			log.Info("list_chain_transactions request sent, waiting for response...")
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "make_chain_address":
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodMakeChainAddress, nil)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send make_chain_address request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		case "pay_chain_address":
			if len(cmdParts) < 3 {
				fmt.Println(errorStyle.Render("Usage: pay_chain_address <address> <amount>"))
				continue
			}
			address := cmdParts[1]
			amount := cmdParts[2]
			params := map[string]interface{}{
				"address": address,
				"amount":  parseInt(amount),
			}
			err := sendNWCRequest(ctx, pool, parsed, clientSecretKey, clientPubKey, MethodPayChainAddress, params)
			if err != nil {
				fmt.Println(errorStyle.Render("Error: ") + "Failed to send pay_chain_address request: " + err.Error())
				continue
			}
			waitForPrettyResponse(responses, clientSecretKey, parsed.WalletPubKey)

		default:
			fmt.Println(errorStyle.Render("Unrecognized command. Try: make_invoice, pay_invoice, get_balance, list_transactions, list_chain_transactions, make_chain_address, pay_chain_address, exit"))
		}
	}
}

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

	event := nostr.Event{
		Kind:      nostr.KindNWCWalletRequest,
		PubKey:    clientPubKey,
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags: nostr.Tags{
			nostr.Tag{"p", nwc.WalletPubKey},
		},
	}
	log.Debug("Signing event with client key")
	event.Sign(clientSecKey)
	log.WithFields(log.Fields{
		"signature": event.Sig,
		"eventID":   event.ID,
	}).Debug("Event signed")

	ok, err := event.CheckSignature()
	if err != nil || !ok {
		log.WithError(err).WithField("valid", ok).Error("Event signature validation failed")
		return fmt.Errorf("event signature validation failed: %v, %w", ok, err)
	}
	log.Debug("Event signature validated successfully")

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
			displayParsedResponse(decrypted)
		}
	case <-time.After(10 * time.Second):
		log.Warn("Timed out waiting for response")
		fmt.Println(errorStyle.Render("Timed out waiting for response."))
	}
}

func decryptResponseContent(ev nostr.Event, clientSecKey, walletPubKey string) (string, error) {
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

	if ev.PubKey != walletPubKey {
		log.WithFields(log.Fields{
			"expectedPubKey": walletPubKey,
			"actualPubKey":   ev.PubKey,
		}).Warn("Response pubkey doesn't match wallet pubkey")
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

func displayParsedResponse(jsonStr string) {
	var resp NWCResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	if err != nil {
		log.WithError(err).Error("Failed to parse response")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse response: " + err.Error())
		return
	}

	if resp.Error != nil {
		fmt.Println(errorStyle.Render("Error: ") + resp.Error.Code + " - " + resp.Error.Message)
		return
	}

	switch resp.ResultType {
	case "get_info":
		displayGetInfoResult(resp.Result)
	case "pay_invoice":
		displayPayInvoiceResult(resp.Result)
	case "make_invoice":
		displayMakeInvoiceResult(resp.Result)
	case "lookup_invoice":
		displayMakeInvoiceResult(resp.Result)
	case "get_balance":
		displayGetBalanceResult(resp.Result)
	case "list_transactions":
		displayListTransactionsResult(resp.Result)
	case "list_chain_transactions":
		displayListChainTransactionsResult(resp.Result)
	default:
		var prettyJSON map[string]interface{}
		json.Unmarshal(resp.Result, &prettyJSON)
		jsonBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")

		fmt.Println(boxStyle.Render(highlightStyle.Render("Result Type: ") + resp.ResultType + "\n\n" + string(jsonBytes)))
	}
}

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

	// Instead of a styled box, we will print the invoice in a plain format
	if result.Invoice != "" {
		content += fmt.Sprintf("\n\n%s\n", result.Invoice) // Add the invoice string directly
	}

	fmt.Println(boxStyle.Render(content)) // Keep the box style for the rest of the content
}

func displayGetBalanceResult(resultJson json.RawMessage) {
	var result GetBalanceResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse get_balance result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse get_balance result: " + err.Error())
		return
	}

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

	transactionsList := subtitleStyle.Render("Recent Transactions") + "\n\n"

	divider := strings.Repeat("─", 50) + "\n"
	transactionsList += divider

	for i, tx := range result.Transactions {
		created := time.Unix(tx.CreatedAt, 0).Format("2006-01-02 15:04:05")
		settled := ""
		if tx.SettledAt > 0 {
			settled = time.Unix(tx.SettledAt, 0).Format("2006-01-02 15:04:05")
		}

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

		if i < len(result.Transactions)-1 {
			transactionsList += divider
		}
	}

	fmt.Println(boxStyle.Render(transactionsList))
}

func displayListChainTransactionsResult(resultJson json.RawMessage) {
	var result ListChainTransactionsResult
	err := json.Unmarshal(resultJson, &result)
	if err != nil {
		log.WithError(err).Error("Failed to parse list_chain_transactions result")
		fmt.Println(errorStyle.Render("Error: ") + "Failed to parse list_chain_transactions result: " + err.Error())
		return
	}

	if len(result.Transactions) == 0 {
		fmt.Println(boxStyle.Render(subtitleStyle.Render("Chain Transactions") + "\n\nNo on-chain transactions found."))
		return
	}

	transactionsList := subtitleStyle.Render("Recent On-Chain Transactions") + "\n\n"

	divider := strings.Repeat("─", 50) + "\n"
	transactionsList += divider

	for i, tx := range result.Transactions {
		typeColor := successColor
		if tx.Type == "outgoing" {
			typeColor = warningColor
		}

		txType := lipgloss.NewStyle().Foreground(typeColor).Bold(true).Render(tx.Type)
		amountStr := fmt.Sprintf("%d sats", tx.Amount)
		if tx.Type == "outgoing" {
			amountStr = "-" + amountStr
		} else {
			amountStr = "+" + amountStr
		}
		amountStyle := lipgloss.NewStyle().Foreground(typeColor).Bold(true).Render(amountStr)

		txidDisplay := "N/A"
		if len(tx.TxID) > 0 {
			if len(tx.TxID) > 16 {
				txidDisplay = tx.TxID[:16] + "..."
			} else {
				txidDisplay = tx.TxID
			}
		}

		txContent := fmt.Sprintf(`%s %s   %s

%s %s
%s %d
%s %s
%s %s`,
			txType,
			txidDisplay,
			amountStyle,

			labelStyle.Render("Transaction ID:"),
			valueStyle.Render(tx.TxID),
			labelStyle.Render("Amount:"),
			tx.Amount,
			labelStyle.Render("Type:"),
			valueStyle.Render(tx.Type),
			labelStyle.Render("Address:"),
			valueStyle.Render(tx.Address),
		)

		transactionsList += txContent + "\n"

		if i < len(result.Transactions)-1 {
			transactionsList += divider
		}
	}

	fmt.Println(boxStyle.Render(transactionsList))
}

func parseInt(s string) int64 {
	var val int64
	fmt.Sscanf(s, "%d", &val)
	log.WithFields(log.Fields{
		"input":  s,
		"parsed": val,
	}).Debug("Parsed integer")
	return val
}
