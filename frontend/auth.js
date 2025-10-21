// Authentication module
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
