# Phishing-Emails-Detection

cat <<'JSONEOF' > /tmp/test_payload.json
{
  "email_content": {
    "from_address": "suspicious@fake-bank.com",
    "from_name": "Bank Security",
    "to": "victim@gmail.com",
    "subject": "Urgent: Verify your account now!",
    "body_text": "Click here to verify your account immediately or it will be suspended. http://fake-bank-login.com/verify",
    "body_html": "",
    "headers": {}
  }
}
JSONEOF

curl -s -X POST https://nonexpediently-nonenumerated-santa.ngrok-free.dev/api/v1/analyze \
     -H "Content-Type: application/json" \
     -H "X-API-Key: my-secret-123" \
     -H "ngrok-skip-browser-warning: true" \
     -d @/tmp/test_payload.json | jq .