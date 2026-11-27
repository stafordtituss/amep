# Create a starter policy and a private signing key.
npx --no-install protect-mcp init --starter

# A normal read is allowed; a force-push to main is denied (exit 2).
npx --no-install protect-mcp evaluate --policy ./protect.cedar --tool Read --input '{"path":"README.md"}'
npx --no-install protect-mcp evaluate --policy ./protect.cedar --tool Bash --input '{"command":"git push --force origin main"}' || test "$?" -eq 2

# Evaluate again at signing time and record both decisions, in order.
npx --no-install protect-mcp sign --cedar builtin:starter --tool Read --input '{"path":"README.md"}' --key ./protect-mcp.key --receipts ./receipts
npx --no-install protect-mcp sign --cedar builtin:starter --tool Bash --input '{"command":"git push --force origin main"}' --key ./protect-mcp.key --receipts ./receipts

# Take only the public key from the key you generated, not from the receipt.
PROTECT_MCP_PUBLIC_KEY=$(node -p 'JSON.parse(require("fs").readFileSync("protect-mcp.key", "utf8")).publicKey')
npx --no-install verify --replay-chain ./receipts/receipts.jsonl --key "$PROTECT_MCP_PUBLIC_KEY" --json

# Change the signed deny to allow. The original receipt log stays intact.
node -e 'const fs=require("fs");const r=JSON.parse(fs.readFileSync("receipts/receipts.jsonl","utf8").trim().split("\n")[1]);r.payload.decision="allow";fs.writeFileSync("tampered.json",JSON.stringify(r))'
npx --no-install verify tampered.json --key "$PROTECT_MCP_PUBLIC_KEY" --json || test "$?" -eq 1
