# Deployment Guide for Web Text Encryption

## GitHub Pages Deployment (Frontend Only)

### Automatic Deployment

The project is configured with GitHub Actions for automatic deployment. Every push to the `main` branch will trigger a deployment.

**Your site will be available at:**
```
https://mehakYahya.github.io/Web-text-Encryption/
```

### Manual Setup Steps

1. **Go to your GitHub repository settings**
   - Navigate to: `Settings` → `Pages`

2. **Configure Source**
   - Source: Deploy from a branch
   - Branch: `main`
   - Folder: `/ (root)` or use GitHub Actions

3. **GitHub Actions (Recommended)**
   - The workflow file is already created at `.github/workflows/deploy.yml`
   - It automatically deploys the `frontend` folder to GitHub Pages
   - No additional configuration needed

### Important Notes for GitHub Pages

⚠️ **Backend Features Won't Work on GitHub Pages**

GitHub Pages only hosts static files. The following features require a backend server:
- User authentication (login/register)
- Saving messages
- Loading saved messages

**What WILL work:**
- All encryption/decryption operations (Caesar, AES, DES, RSA, Base64)
- Hash generation (SHA-256)
- Copy to clipboard
- All UI features and animations

**What WON'T work:**
- Login/Register buttons
- Save message functionality
- View saved messages
- Any authentication features

### For Full Functionality

Deploy the backend separately and update the API URL:

## Backend Deployment Options

### Option 1: Render.com (Recommended - Free Tier)

1. **Sign up at [render.com](https://render.com)**

2. **Create a new Web Service**
   - Connect your GitHub repository
   - Root Directory: `./`
   - Build Command: `npm install`
   - Start Command: `npm start`

3. **Environment Variables** (Optional)
   - `PORT`: Will be set automatically by Render
   - `JWT_SECRET`: Your custom JWT secret
   - `SESSION_SECRET`: Your custom session secret

4. **Update Frontend**
   - Edit `frontend/script.js`
   - Change the API base URL in the Auth class:
   ```javascript
   this.apiBase = 'https://your-app.onrender.com';
   ```

5. **Redeploy GitHub Pages** after updating the API URL

### Option 2: Railway.app

1. **Sign up at [railway.app](https://railway.app)**

2. **Deploy from GitHub**
   - New Project → Deploy from GitHub repo
   - Select your repository
   - Railway auto-detects Node.js

3. **Configure**
   - Start Command: `npm start`
   - Auto-deploy on push: Enable

4. **Update Frontend API URL** (same as above)

### Option 3: Vercel (Serverless)

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Create vercel.json** in root:
   ```json
   {
     "version": 2,
     "builds": [
       {
         "src": "backend/server.js",
         "use": "@vercel/node"
       }
     ],
     "routes": [
       {
         "src": "/(.*)",
         "dest": "backend/server.js"
       }
     ]
   }
   ```

3. **Deploy**
   ```bash
   vercel --prod
   ```

4. **Update Frontend API URL**

### Option 4: Heroku

1. **Install Heroku CLI**
   ```bash
   npm install -g heroku
   ```

2. **Login and Create App**
   ```bash
   heroku login
   heroku create your-app-name
   ```

3. **Add Procfile** in root:
   ```
   web: node backend/server.js
   ```

4. **Deploy**
   ```bash
   git push heroku main
   ```

5. **Update Frontend API URL**

## Testing Your Deployment

### Test GitHub Pages (Frontend)
1. Visit: `https://mehakYahya.github.io/Web-text-Encryption/`
2. Try encryption/decryption without logging in
3. Hash functionality should work

### Test Full Stack (After Backend Deployment)
1. Visit your GitHub Pages URL
2. Click "Register" to create an account
3. Try saving a message
4. Logout and login again
5. Check if saved messages persist

## Troubleshooting

### GitHub Pages Not Loading
- Check repository settings → Pages
- Ensure workflow has run successfully (Actions tab)
- Wait 5-10 minutes for DNS propagation

### Backend Connection Issues
- Check CORS settings in `server.js`
- Ensure API URL is correct in `script.js`
- Check backend logs for errors
- Verify backend is running (visit backend URL directly)

### Authentication Not Working
- Clear browser localStorage
- Check JWT_SECRET is set in backend
- Verify backend URL is accessible from frontend

## Update Deployment

### Update Frontend
```bash
git add .
git commit -m "Update frontend"
git push origin main
```
GitHub Actions will automatically deploy.

### Update Backend
Depends on your hosting platform:
- **Render/Railway**: Push to GitHub (auto-deploy)
- **Vercel**: Run `vercel --prod`
- **Heroku**: `git push heroku main`

## Custom Domain (Optional)

1. **Buy a domain** from any registrar
2. **Add CNAME record** pointing to `mehakYahya.github.io`
3. **Update GitHub Pages settings** with custom domain
4. **Enable HTTPS** in GitHub Pages settings

---

Need help? Open an issue on GitHub!
