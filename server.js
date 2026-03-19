const express = require('express');
const app = express();

app.use(express.json());

// MAIN API
app.post('/analyze', (req, res) => {
    const { code } = req.body;

    let vulnerabilities = [];

    // 🔴 SQL Injection
    if (code.includes("SELECT") && code.includes("+")) {
        vulnerabilities.push({
            type: "SQL Injection",
            severity: "High",
            explanation: "User input is directly concatenated into SQL query.",
            fix: "Use parameterized queries instead of string concatenation.",
            simulation: [
                "User enters: ' OR 1=1 --",
                "Query becomes always TRUE",
                "Authentication is bypassed",
                "Attacker gains access to all data"
            ]
        });
    }

    // 🔐 Hardcoded Secret
    if (code.includes("API_KEY") || code.includes("SECRET") || code.includes("password")) {
        vulnerabilities.push({
            type: "Hardcoded Secret",
            severity: "High",
            explanation: "Sensitive credentials are stored directly in code.",
            fix: "Move secrets to environment variables or secure vaults.",
            simulation: [
                "Attacker accesses source code",
                "Finds hardcoded credentials",
                "Uses them to access system or API",
                "System is compromised without hacking"
            ]
        });
    }

    // 💣 Command Injection
    if (code.includes("os.system") || code.includes("exec(")) {
        vulnerabilities.push({
            type: "Command Injection",
            severity: "High",
            explanation: "User input is passed to system commands without validation.",
            fix: "Sanitize input and avoid direct shell execution.",
            simulation: [
                "User inputs malicious command",
                "System executes injected command",
                "Attacker gains system-level access",
                "Files or system can be modified/deleted"
            ]
        });
    }

    res.json({ vulnerabilities });
});

// START SERVER
app.listen(3000, () => {
    console.log("Backend running on http://localhost:3000");
});