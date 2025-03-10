# NWC Tools

NWC Tools is a command-line interface for interacting with Lightning Network wallets via the Nostr Wallet Connect (NWC) protocol. This tool allows you to manage your Lightning wallet, create invoices, make payments, and more, all through a simple terminal interface.

## Features

- Connect to any NWC-compatible wallet
- Create Lightning invoices
- Pay Lightning invoices
- Check wallet balance
- List transaction history
- Generate on-chain addresses

## Installation

### Option 1: Install using Go (Recommended)

If you have Go installed (version 1.19 or newer), you can install NWC Tools directly:

```bash
go install github.com/bitvora/nwc-tools@latest
```

This will download, compile, and install the `nwc-tools` binary in your `$GOPATH/bin` directory. Make sure this directory is in your system's PATH.

### Option 2: Build from Source

1. Clone the repository:

```bash
git clone https://github.com/bitvora/nwc-tools.git
cd nwc-tools
```

2. Build the application:

```bash
go build -o nwc-tools
```

3. Optionally, move the binary to a location in your PATH:

```bash
sudo mv nwc-tools /usr/local/bin/
```

## Usage

Run the tool:

```bash
nwc-tools
```

You will be prompted to enter a Nostr Wallet Connect URL, which looks something like:
```
nostr+walletconnect://<pubkey>?relay=<relayURL>&secret=<secretKey>
```

You can get this URL from your compatible Lightning wallet.

### Available Commands

Once connected, you can use the following commands:

- `make_invoice <amount_msat> <description> [<expiry_seconds>]` - Create a new Lightning invoice
- `pay_invoice <lightning_invoice_string>` - Pay a Lightning invoice
- `get_balance` - Check your wallet's current balance
- `list_transactions` - View recent transactions
- `make_chain_address` - Generate a new on-chain Bitcoin address
- `exit` - Close the application

### Command-line Options

You can specify log level when starting the application:

```bash
nwc-tools --loglevel=debug
```

Available log levels: `debug`, `info`, `warn`, `error`

## Examples

### Creating an Invoice

```
nwc> make_invoice 50000 "Test invoice" 3600
```
This creates an invoice for 50,000 millisatoshis (50 sats) with a description "Test invoice" that expires in 3600 seconds (1 hour).

### Paying an Invoice

```
nwc> pay_invoice lnbc500n1p3qz7typp5...
```

### Checking Balance

```
nwc> get_balance
```

## License

This project is open source and available under the [MIT License](LICENSE.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
