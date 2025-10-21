// ========== Authentication Module ==========
class Auth {
	constructor() {
		this.token = localStorage.getItem('authToken');
		this.username = localStorage.getItem('username');
		this.apiBase = 'http://localhost:3001';
		if (typeof window !== 'undefined' && window.location && window.location.port === '3001') {
			this.apiBase = window.location.origin;
		}
	}

	isAuthenticated() {
		return !!this.token;
	}

	getUsername() {
		return this.username;
	}

	getToken() {
		return this.token;
	}

	async register(username, password) {
		try {
			const res = await fetch(`${this.apiBase}/api/register`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ username, password })
			});
			const data = await res.json();
			
			if (data.error) {
				throw new Error(data.error);
			}
			
			this.token = data.token;
			this.username = data.username;
			localStorage.setItem('authToken', this.token);
			localStorage.setItem('username', this.username);
			
			return { success: true, username: this.username };
		} catch (error) {
			return { success: false, error: error.message };
		}
	}

	async login(username, password) {
		try {
			const res = await fetch(`${this.apiBase}/api/login`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ username, password })
			});
			const data = await res.json();
			
			if (data.error) {
				throw new Error(data.error);
			}
			
			this.token = data.token;
			this.username = data.username;
			localStorage.setItem('authToken', this.token);
			localStorage.setItem('username', this.username);
			
			return { success: true, username: this.username };
		} catch (error) {
			return { success: false, error: error.message };
		}
	}

	logout() {
		this.token = null;
		this.username = null;
		localStorage.removeItem('authToken');
		localStorage.removeItem('username');
	}

	async saveMessage(messageData) {
		if (!this.isAuthenticated()) {
			return { success: false, error: 'Not authenticated' };
		}

		try {
			const res = await fetch(`${this.apiBase}/api/messages/save`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${this.token}`
				},
				body: JSON.stringify(messageData)
			});
			const data = await res.json();
			
			if (data.error) {
				throw new Error(data.error);
			}
			
			return { success: true, message: data.message };
		} catch (error) {
			return { success: false, error: error.message };
		}
	}

	async getMessages() {
		if (!this.isAuthenticated()) {
			return { success: false, error: 'Not authenticated' };
		}

		try {
			const res = await fetch(`${this.apiBase}/api/messages`, {
				method: 'GET',
				headers: {
					'Authorization': `Bearer ${this.token}`
				}
			});
			const data = await res.json();
			
			if (data.error) {
				throw new Error(data.error);
			}
			
			return { success: true, messages: data.messages };
		} catch (error) {
			return { success: false, error: error.message };
		}
	}

	async deleteMessage(messageId) {
		if (!this.isAuthenticated()) {
			return { success: false, error: 'Not authenticated' };
		}

		try {
			const res = await fetch(`${this.apiBase}/api/messages/${messageId}`, {
				method: 'DELETE',
				headers: {
					'Authorization': `Bearer ${this.token}`
				}
			});
			const data = await res.json();
			
			if (data.error) {
				throw new Error(data.error);
			}
			
			return { success: true };
		} catch (error) {
			return { success: false, error: error.message };
		}
	}
}

// Initialize auth instance
const auth = new Auth();

// ========== Main Application ==========
// Prefer backend on port 3001. If the page itself is served from port 3001 use that origin.
let apiBase = 'http://localhost:3001';
if (typeof window !== 'undefined' && window.location && window.location.port === '3001') {
	apiBase = window.location.origin;
}

const inputText = document.getElementById('inputText');
const outputText = document.getElementById('outputText');
const cipherTextInput = document.getElementById('cipherText');
const decryptedText = document.getElementById('decryptedText');
const methodSelect = document.getElementById('method');
const shiftInput = document.getElementById('shift');
const passphraseInput = document.getElementById('passphrase');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const copyEncryptedBtn = document.getElementById('copyEncryptedBtn');
const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');
const clearBtn = document.getElementById('clearBtn');
const hashBtn = document.getElementById('hashBtn');
const saveBtn = document.getElementById('saveBtn');
const viewSavedBtn = document.getElementById('viewSavedBtn');
const feedback = document.getElementById('feedback');

// Auth UI elements
const authBar = document.getElementById('authBar');
const authStatus = document.getElementById('authStatus');
const authButtons = document.getElementById('authButtons');
const authModal = document.getElementById('authModal');
const authModalTitle = document.getElementById('authModalTitle');
const authUsername = document.getElementById('authUsername');
const authPassword = document.getElementById('authPassword');
const authSubmit = document.getElementById('authSubmit');
const authCancel = document.getElementById('authCancel');
const authToggle = document.getElementById('authToggle');
const authToggleText = document.getElementById('authToggleText');
const authError = document.getElementById('authError');
const savedModal = document.getElementById('savedModal');
const closeSavedModal = document.getElementById('closeSavedModal');
const savedMessagesList = document.getElementById('savedMessagesList');

let isLoginMode = true;
const hero = document.querySelector('.hero');
const blob1 = document.querySelector('.blob.b1');
const blob2 = document.querySelector('.blob.b2');
const canvas = document.getElementById('animCanvas');
let ctx = null;
if (canvas) {
	canvas.width = canvas.clientWidth * devicePixelRatio;
	canvas.height = canvas.clientHeight * devicePixelRatio;
	ctx = canvas.getContext('2d');
	ctx.scale(devicePixelRatio, devicePixelRatio);
}

// Toast notification helper
let feedbackTimeout = null;
function showFeedback(message, type = 'info') {
	if (feedbackTimeout) clearTimeout(feedbackTimeout);
	feedback.textContent = message;
	feedback.className = 'show';
	if (type === 'success') feedback.classList.add('success');
	if (type === 'error') feedback.classList.add('error');
	
	feedbackTimeout = setTimeout(() => {
		feedback.classList.remove('show', 'success', 'error');
	}, 3000);
}

function showFieldForMethod(method) {
	shiftInput.style.display = 'none';
	passphraseInput.style.display = 'none';
	if (method === 'caesar') shiftInput.style.display = 'inline-block';
	if (['aes', 'des', 'rsa'].includes(method)) passphraseInput.style.display = 'inline-block';
}

methodSelect.addEventListener('change', (e) => showFieldForMethod(e.target.value));

function validate(method, text, forDecrypt = false) {
	if (!text || !text.trim()) {
		showFeedback(forDecrypt ? 'Ciphertext is required' : 'Plain text is required', 'error');
		return false;
	}
	if (!method) {
		showFeedback('Please select an algorithm', 'error');
		return false;
	}
	if (method === 'caesar' && shiftInput.value === '') {
		showFeedback('Please provide a numeric shift for Caesar', 'error');
		return false;
	}
	if (['aes', 'des', 'rsa'].includes(method) && passphraseInput.value === '') {
		showFeedback('Please provide a passphrase for ' + method.toUpperCase(), 'error');
		return false;
	}
	return true;
}

async function callApi(path, body) {
	try {
		const res = await fetch(apiBase + path, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body)
		});
		return await res.json();
	} catch (e) {
		return { error: 'Server unreachable' };
	}
}

encryptBtn.addEventListener('click', async () => {
	const method = methodSelect.value;
	const text = inputText.value;
	if (!validate(method, text)) return;

	const options = {};
	if (method === 'caesar') options.shift = parseInt(shiftInput.value, 10);
	if (['aes', 'des', 'rsa'].includes(method)) options.passphrase = passphraseInput.value;

	const result = await callApi('/encrypt', { method, text, options });
	if (result.error) showFeedback(result.error, 'error');
	else {
		outputText.value = result.ciphertext || '';
		// also pre-fill ciphertext box so users can decrypt separately if they want
		if (cipherTextInput) cipherTextInput.value = result.ciphertext || '';
		showFeedback('✓ Encrypted successfully!', 'success');
		// ui flourish on success
		triggerParticleBurst();
	}
});


decryptBtn.addEventListener('click', async () => {
	const method = methodSelect.value;
	const text = (cipherTextInput && cipherTextInput.value && cipherTextInput.value.trim()) ? cipherTextInput.value : inputText.value;
	if (!validate(method, text, true)) return;

	const options = {};
	if (method === 'caesar') options.shift = parseInt(shiftInput.value, 10);
	if (['aes', 'des', 'rsa'].includes(method)) options.passphrase = passphraseInput.value;

	const result = await callApi('/decrypt', { method, text, options });
	if (result.error) showFeedback(result.error, 'error');
	else {
		decryptedText.value = result.plaintext || '';
		showFeedback('✓ Decrypted successfully!', 'success');
	}
});

if (copyEncryptedBtn) {
	copyEncryptedBtn.addEventListener('click', async () => {
		const toCopy = outputText.value;
		if (!toCopy) return;
		try {
			await navigator.clipboard.writeText(toCopy);
			showFeedback('✓ Text copied!', 'success');
			triggerPulse();
		} catch (e) {
			showFeedback('Copy failed', 'error');
		}
	});
}

if (copyDecryptedBtn) {
	copyDecryptedBtn.addEventListener('click', async () => {
		const toCopy = decryptedText.value;
		if (!toCopy) return;
		try {
			await navigator.clipboard.writeText(toCopy);
			showFeedback('✓ Text copied!', 'success');
			triggerPulse();
		} catch (e) {
			showFeedback('Copy failed', 'error');
		}
	});
}


clearBtn.addEventListener('click', () => {
	inputText.value = '';
	outputText.value = '';
	if (cipherTextInput) cipherTextInput.value = '';
	decryptedText.value = '';
	passphraseInput.value = '';
	shiftInput.value = '';
	showFeedback('✓ Cleared', 'success');
});

// show fields on load if preselected
showFieldForMethod(methodSelect.value);

// ========== Authentication UI ==========
function updateAuthUI() {
	if (auth.isAuthenticated()) {
		authStatus.innerHTML = `<span class="text-green-400">👤 ${auth.getUsername()}</span>`;
		authButtons.innerHTML = '<button id="logoutBtn" class="text-sm bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-white">Logout</button>';
		document.getElementById('logoutBtn').addEventListener('click', handleLogout);
		saveBtn.style.display = 'inline-block';
		viewSavedBtn.style.display = 'inline-block';
	} else {
		authStatus.innerHTML = '<span class="text-slate-400">Not logged in</span>';
		authButtons.innerHTML = `
			<button id="loginBtn" class="text-sm bg-indigo-600 hover:bg-indigo-700 px-3 py-1 rounded text-white">Login</button>
			<button id="registerBtn" class="text-sm bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-white">Register</button>
		`;
		document.getElementById('loginBtn').addEventListener('click', () => showAuthModal(true));
		document.getElementById('registerBtn').addEventListener('click', () => showAuthModal(false));
		saveBtn.style.display = 'none';
		viewSavedBtn.style.display = 'none';
	}
}

function showAuthModal(loginMode) {
	isLoginMode = loginMode;
	authModalTitle.textContent = loginMode ? 'Login' : 'Register';
	authSubmit.textContent = loginMode ? 'Login' : 'Register';
	authToggleText.textContent = loginMode ? "Don't have an account?" : "Already have an account?";
	authToggle.textContent = loginMode ? 'Register' : 'Login';
	authUsername.value = '';
	authPassword.value = '';
	authError.textContent = '';
	authModal.style.display = 'flex';
}

function hideAuthModal() {
	authModal.style.display = 'none';
}

async function handleAuthSubmit() {
	const username = authUsername.value.trim();
	const password = authPassword.value;
	
	if (!username || !password) {
		authError.textContent = 'Please fill in all fields';
		return;
	}
	
	authError.textContent = '';
	authSubmit.disabled = true;
	authSubmit.textContent = 'Processing...';
	
	let result;
	if (isLoginMode) {
		result = await auth.login(username, password);
	} else {
		result = await auth.register(username, password);
	}
	
	authSubmit.disabled = false;
	authSubmit.textContent = isLoginMode ? 'Login' : 'Register';
	
	if (result.success) {
		hideAuthModal();
		updateAuthUI();
		showFeedback(`✓ Welcome, ${result.username}!`, 'success');
	} else {
		authError.textContent = result.error || 'Authentication failed';
	}
}

function handleLogout() {
	auth.logout();
	updateAuthUI();
	
	// Clear all input and output fields
	inputText.value = '';
	outputText.value = '';
	if (cipherTextInput) cipherTextInput.value = '';
	decryptedText.value = '';
	passphraseInput.value = '';
	shiftInput.value = '';
	methodSelect.value = '';
	
	// Hide passphrase and shift inputs
	showFieldForMethod('');
	
	showFeedback('✓ Logged out successfully', 'success');
}

authSubmit.addEventListener('click', handleAuthSubmit);
authCancel.addEventListener('click', hideAuthModal);
authToggle.addEventListener('click', () => {
	showAuthModal(!isLoginMode);
});

// Enter key support
authUsername.addEventListener('keypress', (e) => {
	if (e.key === 'Enter') handleAuthSubmit();
});
authPassword.addEventListener('keypress', (e) => {
	if (e.key === 'Enter') handleAuthSubmit();
});

// ========== Save Message Feature ==========
if (saveBtn) {
	saveBtn.addEventListener('click', async () => {
		if (!auth.isAuthenticated()) {
			showFeedback('Please login to save messages', 'error');
			return;
		}
		
		const encryptedText = outputText.value;
		if (!encryptedText) {
			showFeedback('No encrypted message to save', 'error');
			return;
		}
		
		const title = prompt('Enter a title for this message:') || 'Untitled';
		
		const messageData = {
			title,
			method: methodSelect.value,
			encryptedText,
			originalText: inputText.value,
			timestamp: new Date().toISOString()
		};
		
		const result = await auth.saveMessage(messageData);
		if (result.success) {
			showFeedback('✓ Message saved successfully!', 'success');
		} else {
			showFeedback('Failed to save: ' + result.error, 'error');
		}
	});
}

// ========== View Saved Messages ==========
if (viewSavedBtn) {
	viewSavedBtn.addEventListener('click', async () => {
		if (!auth.isAuthenticated()) {
			showFeedback('Please login to view saved messages', 'error');
			return;
		}
		
		const result = await auth.getMessages();
		if (result.success) {
			displaySavedMessages(result.messages);
			savedModal.style.display = 'flex';
		} else {
			showFeedback('Failed to load messages: ' + result.error, 'error');
		}
	});
}

closeSavedModal.addEventListener('click', () => {
	savedModal.style.display = 'none';
});

function displaySavedMessages(messages) {
	if (messages.length === 0) {
		savedMessagesList.innerHTML = '<p class="text-center text-slate-400">No saved messages yet</p>';
		return;
	}
	
	savedMessagesList.innerHTML = messages.reverse().map(msg => `
		<div class="glass p-4 rounded-lg">
			<div class="flex justify-between items-start mb-2">
				<div>
					<h3 class="font-bold text-lg">${escapeHtml(msg.title)}</h3>
					<p class="text-xs text-slate-400">Method: ${msg.method} | Saved: ${new Date(msg.saved).toLocaleString()}</p>
				</div>
				<button class="delete-msg bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-sm" data-id="${msg.id}">Delete</button>
			</div>
			<div class="text-sm">
				<p class="mb-1"><strong>Encrypted:</strong></p>
				<p class="bg-slate-900 p-2 rounded break-all text-xs">${escapeHtml(msg.encryptedText)}</p>
				${msg.originalText ? `<p class="mt-2 mb-1"><strong>Original:</strong></p>
				<p class="bg-slate-900 p-2 rounded break-all text-xs">${escapeHtml(msg.originalText)}</p>` : ''}
			</div>
		</div>
	`).join('');
	
	// Add delete handlers
	document.querySelectorAll('.delete-msg').forEach(btn => {
		btn.addEventListener('click', async (e) => {
			const id = e.target.getAttribute('data-id');
			if (confirm('Delete this message?')) {
				const result = await auth.deleteMessage(id);
				if (result.success) {
					// Reload messages
					const refreshResult = await auth.getMessages();
					if (refreshResult.success) {
						displaySavedMessages(refreshResult.messages);
					}
				}
			}
		});
	});
}

function escapeHtml(text) {
	const div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

// Initialize auth UI on page load
updateAuthUI();

// Helper: compute SHA-256 hex digest using Web Crypto
async function sha256Hex(str) {
	const enc = new TextEncoder();
	const data = enc.encode(str);
	const hashBuf = await crypto.subtle.digest('SHA-256', data);
	const hashArr = Array.from(new Uint8Array(hashBuf));
	return hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
}

if (hashBtn) {
	hashBtn.addEventListener('click', async () => {
		const text = inputText.value;
		
		if (!text || !text.trim()) {
			showFeedback('Plain text is required to hash', 'error');
			return;
		}
		
		try {
			// Always use SHA-256 for the hash button
			const digest = await sha256Hex(text);
			
			// show the digest in the encrypted output and ciphertext box so users can copy/use it
			outputText.value = digest;
			if (cipherTextInput) cipherTextInput.value = digest;
			showFeedback('✓ SHA-256 hash computed successfully!', 'success');
			triggerParticleBurst();
		} catch (e) {
			showFeedback('Hash failed', 'error');
		}
	});
}

	// small helper: pulse container when copying
	function triggerPulse() {
		const el = document.querySelector('.container');
		if (!el) return;
		el.animate([
			{ transform: 'scale(1)' },
			{ transform: 'scale(1.01)' },
			{ transform: 'scale(1)' }
		], { duration: 320, easing: 'cubic-bezier(.2,.8,.2,1)' });
	}

	// particle burst implementation (lightweight)
	function triggerParticleBurst() {
		if (!ctx) return;
		const particles = [];
		const rect = canvas.getBoundingClientRect();
		const cx = rect.width - 60;
		const cy = 40;
		const colors = ['#7c5cff', '#6ad6ff', '#9fd8ff', '#cfa8ff'];
		for (let i = 0; i < 18; i++) {
			particles.push({
				x: cx,
				y: cy,
				vx: (Math.random() - 0.5) * 6,
				vy: -Math.random() * 6 - 1,
				life: 60 + Math.random() * 40,
				size: 4 + Math.random() * 6,
				color: colors[Math.floor(Math.random() * colors.length)]
			});
		}
		let frames = 0;
		function frame() {
			frames++;
			ctx.clearRect(0, 0, canvas.width, canvas.height);
			particles.forEach(p => {
				p.x += p.vx;
				p.y += p.vy;
				p.vy += 0.12; // gravity
				p.life -= 1;
				ctx.beginPath();
				ctx.fillStyle = p.color;
				ctx.globalAlpha = Math.max(0, p.life / 100);
				ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
				ctx.fill();
			});
			// remove dead
			for (let i = particles.length - 1; i >= 0; i--) if (particles[i].life <= 0) particles.splice(i, 1);
			if (particles.length > 0 && frames < 180) requestAnimationFrame(frame);
			else ctx.clearRect(0,0,canvas.width,canvas.height);
		}
		requestAnimationFrame(frame);
	}

	// blob parallax on mouse move
	if (hero && (blob1 || blob2)) {
		hero.addEventListener('mousemove', (ev) => {
			const r = hero.getBoundingClientRect();
			const px = (ev.clientX - r.left) / r.width - 0.5;
			const py = (ev.clientY - r.top) / r.height - 0.5;
			if (blob1) blob1.style.transform = `translate(${8 + px * 18}px, ${8 + py * 12}px) rotate(${px * 6}deg)`;
			if (blob2) blob2.style.transform = `translate(${-12 + px * -14}px, ${-14 + py * -10}px) rotate(${py * -6}deg)`;
		});
		hero.addEventListener('mouseleave', () => {
			if (blob1) blob1.style.transform = '';
			if (blob2) blob2.style.transform = '';
		});
	}

	// add keyboard ripple for accessibility (space/enter)
	document.querySelectorAll('.ripple').forEach(btn => {
		btn.addEventListener('keydown', (e) => {
			if (e.key === 'Enter' || e.key === ' ') {
				btn.classList.add('active-ripple');
				setTimeout(() => btn.classList.remove('active-ripple'), 250);
			}
		});
	});

