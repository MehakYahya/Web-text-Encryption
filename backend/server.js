const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const CryptoJS = require('crypto-js');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');

const app = express();
app.use(cors({
	origin: true,
	credentials: true
}));
app.use(bodyParser.json());
app.use(session({
	secret: 'encryption-secret-key-change-in-production',
	resave: false,
	saveUninitialized: false,
	cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// In-memory storage (for demo - use a real database in production)
const users = new Map(); // username -> { password: hashedPassword, messages: [] }
const JWT_SECRET = 'jwt-secret-change-in-production';

// Serve frontend static files (so client and API share the same origin)
const frontendPath = path.join(__dirname, '..', 'frontend');

// Helpers
function caesarEncrypt(text, shift) {
	if (typeof text !== 'string') return '';
	shift = ((shift % 26) + 26) % 26;
	return text.split('').map(ch => {
		const code = ch.charCodeAt(0);
		// A-Z
		if (code >= 65 && code <= 90) {
			return String.fromCharCode(((code - 65 + shift) % 26) + 65);
		}
		// a-z
		if (code >= 97 && code <= 122) {
			return String.fromCharCode(((code - 97 + shift) % 26) + 97);
		}
		return ch;
	}).join('');
}

function caesarDecrypt(text, shift) {
	return caesarEncrypt(text, -shift);
}

function aesEncrypt(text, passphrase) {
	return CryptoJS.AES.encrypt(text, passphrase).toString();
}

function aesDecrypt(ciphertext, passphrase) {
	try {
		const bytes = CryptoJS.AES.decrypt(ciphertext, passphrase);
		const plaintext = bytes.toString(CryptoJS.enc.Utf8);
		return plaintext;
	} catch (e) {
		return '';
	}
}

function base64Encode(text) {
	return Buffer.from(text, 'utf8').toString('base64');
}

function base64Decode(text) {
	try {
		return Buffer.from(text, 'base64').toString('utf8');
	} catch (e) {
		return '';
	}
}

function sha256Hash(text) {
	return CryptoJS.SHA256(text).toString(CryptoJS.enc.Hex);
}


function desEncrypt(text, passphrase) {
	return CryptoJS.DES.encrypt(text, passphrase).toString();
}

function desDecrypt(ciphertext, passphrase) {
	try {
		const bytes = CryptoJS.DES.decrypt(ciphertext, passphrase);
		const plaintext = bytes.toString(CryptoJS.enc.Utf8);
		return plaintext;
	} catch (e) {
		return '';
	}
}

function tripleDesEncrypt(text, passphrase) {
	return CryptoJS.TripleDES.encrypt(text, passphrase).toString();
}

function tripleDesDecrypt(ciphertext, passphrase) {
	try {
		const bytes = CryptoJS.TripleDES.decrypt(ciphertext, passphrase);
		const plaintext = bytes.toString(CryptoJS.enc.Utf8);
		return plaintext;
	} catch (e) {
		return '';
	}
}

function rsaEncrypt(text, passphrase) {
	
	const key = CryptoJS.SHA256(passphrase).toString();
	return CryptoJS.AES.encrypt(text, key).toString();
}

function rsaDecrypt(ciphertext, passphrase) {
	try {
		const key = CryptoJS.SHA256(passphrase).toString();
		const bytes = CryptoJS.AES.decrypt(ciphertext, key);
		const plaintext = bytes.toString(CryptoJS.enc.Utf8);
		return plaintext;
	} catch (e) {
		return '';
	}
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];
	
	if (!token) {
		return res.status(401).json({ error: 'Authentication required' });
	}
	
	jwt.verify(token, JWT_SECRET, (err, user) => {
		if (err) {
			return res.status(403).json({ error: 'Invalid or expired token' });
		}
		req.user = user;
		next();
	});
}

// User Registration
app.post('/api/register', async (req, res) => {
	const { username, password } = req.body;
	
	if (!username || !password) {
		return res.status(400).json({ error: 'Username and password required' });
	}
	
	if (username.length < 3 || password.length < 6) {
		return res.status(400).json({ error: 'Username must be 3+ chars, password 6+ chars' });
	}
	
	if (users.has(username)) {
		return res.status(400).json({ error: 'Username already exists' });
	}
	
	const hashedPassword = await bcrypt.hash(password, 10);
	users.set(username, {
		password: hashedPassword,
		messages: []
	});
	
	const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
	res.json({ success: true, token, username });
});

// User Login
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body;
	
	if (!username || !password) {
		return res.status(400).json({ error: 'Username and password required' });
	}
	
	const user = users.get(username);
	if (!user) {
		return res.status(401).json({ error: 'Invalid credentials' });
	}
	
	const validPassword = await bcrypt.compare(password, user.password);
	if (!validPassword) {
		return res.status(401).json({ error: 'Invalid credentials' });
	}
	
	const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
	res.json({ success: true, token, username });
});

// Save encrypted message
app.post('/api/messages/save', authenticateToken, (req, res) => {
	const { title, method, encryptedText, originalText, timestamp } = req.body;
	const username = req.user.username;
	
	if (!encryptedText) {
		return res.status(400).json({ error: 'Encrypted text required' });
	}
	
	const user = users.get(username);
	if (!user) {
		return res.status(404).json({ error: 'User not found' });
	}
	
	const message = {
		id: Date.now() + Math.random().toString(36).substr(2, 9),
		title: title || 'Untitled Message',
		method: method || 'unknown',
		encryptedText,
		originalText: originalText || '',
		timestamp: timestamp || new Date().toISOString(),
		saved: new Date().toISOString()
	};
	
	user.messages.push(message);
	res.json({ success: true, message });
});

// Get all saved messages
app.get('/api/messages', authenticateToken, (req, res) => {
	const username = req.user.username;
	const user = users.get(username);
	
	if (!user) {
		return res.status(404).json({ error: 'User not found' });
	}
	
	res.json({ messages: user.messages });
});

// Delete a saved message
app.delete('/api/messages/:id', authenticateToken, (req, res) => {
	const username = req.user.username;
	const messageId = req.params.id;
	const user = users.get(username);
	
	if (!user) {
		return res.status(404).json({ error: 'User not found' });
	}
	
	const index = user.messages.findIndex(m => m.id === messageId);
	if (index === -1) {
		return res.status(404).json({ error: 'Message not found' });
	}
	
	user.messages.splice(index, 1);
	res.json({ success: true });
});

app.post('/encrypt', (req, res) => {
	const { method, text, options } = req.body || {};
	if (!text || !text.trim()) return res.status(400).json({ error: 'Text is required' });
	if (!method) return res.status(400).json({ error: 'Method is required' });

	let result = '';
	switch (method) {
		case 'caesar':
			if (!options || typeof options.shift !== 'number') return res.status(400).json({ error: 'Shift (number) required for Caesar' });
			result = caesarEncrypt(text, options.shift);
			break;
		case 'aes':
			if (!options || !options.passphrase) return res.status(400).json({ error: 'Passphrase required for AES' });
			result = aesEncrypt(text, options.passphrase);
			break;
		case 'des':
			if (!options || !options.passphrase) return res.status(400).json({ error: 'Passphrase required for DES' });
			result = desEncrypt(text, options.passphrase);
			break;
		case 'rsa':
			if (!options || !options.passphrase) return res.status(400).json({ error: 'Passphrase required for RSA' });
			result = rsaEncrypt(text, options.passphrase);
			break;
		case 'base64':
			result = base64Encode(text);
			break;
		case 'sha256':
			result = sha256Hash(text);
			break;
		default:
			return res.status(400).json({ error: 'Unsupported method' });
	}

	return res.json({ ciphertext: result });
});

app.post('/decrypt', (req, res) => {
	const { method, text, options } = req.body || {};
	if (!text || !text.trim()) return res.status(400).json({ error: 'Ciphertext is required' });
	if (!method) return res.status(400).json({ error: 'Method is required' });

	let result = '';
	switch (method) {
		case 'caesar':
			if (!options || typeof options.shift !== 'number') return res.status(400).json({ error: 'Shift (number) required for Caesar' });
			result = caesarDecrypt(text, options.shift);
			break;
		case 'aes':
			if (!options || !options.passphrase) return res.status(400).json({ error: 'Passphrase required for AES' });
			result = aesDecrypt(text, options.passphrase);
			break;
		case 'des':
			if (!options || !options.passphrase) return res.status(400).json({ error: 'Passphrase required for DES' });
			result = desDecrypt(text, options.passphrase);
			break;
		case 'rsa':
			if (!options || !options.passphrase) return res.status(400).json({ error: 'Passphrase required for RSA' });
			result = rsaDecrypt(text, options.passphrase);
			break;
		case 'base64':
			result = base64Decode(text);
			break;
		case 'sha256':
			return res.status(400).json({ error: "SHA-256 is a hash and cannot be decrypted" });
		default:
			return res.status(400).json({ error: 'Unsupported method' });
	}

	return res.json({ plaintext: result });
});

	// Serve frontend static files (so client and API share the same origin)
	app.use(express.static(frontendPath));

	// SPA fallback - serve index.html for unmatched routes
	app.get('*', (req, res) => {
		res.sendFile(path.join(frontendPath, 'index.html'));
	});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

