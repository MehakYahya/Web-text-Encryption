# Web Text Encryption

A modern web-based text encryption and decryption tool with user authentication and message storage capabilities.

## 🚀 Features

### Encryption Algorithms
- **Caesar Cipher** - Classic shift cipher
- **AES-256** - Advanced Encryption Standard
- **DES** - Data Encryption Standard
- **RSA** - Public Key Encryption (simplified)
- **Base64** - Binary-to-text encoding
- **SHA-256** - Secure hash function

### Core Features
- ✅ User authentication (register/login with JWT)
- ✅ Save and manage encrypted messages
- ✅ Beautiful glass-morphism UI with animations
- ✅ Toast notifications for user feedback
- ✅ Copy to clipboard functionality
- ✅ Responsive design for all devices
- ✅ Real-time encryption/decryption

## 📦 Installation

### Local Development

1. **Clone the repository**
```bash
git clone https://github.com/MehakYahya/Web-text-Encryption.git
cd Web-text-Encryption
```

2. **Install dependencies**
```bash
npm install
```

3. **Start the server**
```bash
npm start
```

4. **Open your browser**
Navigate to `http://localhost:3001`

## 🌐 GitHub Pages Deployment

This project can be deployed to GitHub Pages for the frontend, but note that the backend features (authentication and message storage) will not work without a backend server.

### Deploy Frontend Only (Static Version)

The frontend is automatically deployed to GitHub Pages when you push to the main branch.

**Live Demo:** `https://mehakYahya.github.io/Web-text-Encryption/`

### Full Deployment (With Backend)

For full functionality including authentication and saved messages, you need to deploy the backend separately:

**Recommended Backend Hosting:**
- [Render](https://render.com) (Free tier available)
- [Railway](https://railway.app)
- [Heroku](https://heroku.com)
- [Vercel](https://vercel.com) (Serverless functions)

**Steps:**
1. Deploy the backend to your chosen platform
2. Update the API endpoint in `frontend/script.js`:
```javascript
// Change this line in the Auth class constructor:
this.apiBase = 'https://your-backend-url.com';
```

## 🎨 Usage

### Encryption
1. Enter your text in the "Plain Text" field
2. Select an encryption algorithm from the dropdown
3. Provide required parameters (shift for Caesar, passphrase for AES/DES/RSA)
4. Click "Encrypt" button
5. Copy the encrypted text from the output

### Decryption
1. Paste encrypted text in the "Plain Text" field
2. Select the same algorithm used for encryption
3. Provide the same parameters
4. Click "Decrypt" button
5. View the decrypted text

### Hashing
1. Enter text in the "Plain Text" field
2. Click "Hash" button
3. Get SHA-256 hash (one-way, cannot be decrypted)

### User Authentication
1. Click "Register" to create an account
2. Login with your credentials
3. Save encrypted messages for later
4. View and manage saved messages

## 🔧 Configuration

### Backend Configuration
Edit `backend/server.js` to change:
- Port number (default: 3001)
- JWT secret key
- Session secret
- CORS settings

### Frontend Configuration
Edit `frontend/script.js` to change:
- API base URL
- Toast notification duration
- Animation settings

## 📁 Project Structure

```
Web-text-Encryption/
├── frontend/
│   ├── index.html          # Main HTML file
│   ├── script.js           # JavaScript logic + Auth
│   └── style.css           # Styles (if separate)
├── backend/
│   └── server.js           # Express server with encryption APIs
├── .github/
│   └── workflows/
│       └── deploy.yml      # GitHub Actions for deployment
├── package.json            # Dependencies
└── README.md              # This file
```

## 🔒 Security Notes

⚠️ **Important:** This project is for **educational purposes only**.

- Passwords are stored with bcrypt hashing
- JWT tokens are used for authentication
- In-memory storage (not persistent) - use a real database in production
- AES/DES/RSA use passphrases (not production-grade key exchange)
- HTTPS should be used in production
- Never use this for sensitive data in production

## 🛠️ Technologies Used

- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Tailwind CSS
- **Backend:** Node.js, Express.js
- **Encryption:** crypto-js, bcryptjs
- **Authentication:** JWT (jsonwebtoken)
- **Session Management:** express-session

## 📄 License

This project is open source and available under the MIT License.

## 👤 Author

**Mehak Yahya**
- GitHub: [@MehakYahya](https://github.com/MehakYahya)

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Notes

- SHA-256 and other hashes are one-way functions (cannot be decrypted)
- User data is stored in memory and will be lost when server restarts
- For production use, implement a proper database (MongoDB, PostgreSQL, etc.)
- Add rate limiting and input validation for production deployment

---

Made with ❤️ by Mehak Yahya

