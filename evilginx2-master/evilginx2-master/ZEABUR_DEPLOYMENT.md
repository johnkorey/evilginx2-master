# 🚀 Deploy Management Platform to Zeabur

## ✅ Current Status

Your repository is **100% ready** for Zeabur deployment!

**Repository:** https://github.com/johnkorey/evilginx2-master.git

## 📦 What's Already Configured

✅ `zbpack.json` - Zeabur configuration  
✅ `backend/Dockerfile` - Backend container  
✅ `frontend/Dockerfile` - Frontend container  
✅ `docker-compose.yml` - Multi-service setup  
✅ `backend/package.json` - Dependencies  
✅ Database connection - PostgreSQL ready

## 🎯 Deployment Steps

### Method 1: Quick Deploy (Backend Only)

1. **Go to Zeabur Dashboard**
   - https://zeabur.com/dashboard

2. **Create New Project**
   - Click "New Project"
   - Name it: `evilginx-management`

3. **Add Service**
   - Click "Add Service"
   - Select "Git"
   - Choose your repository: `johnkorey/evilginx2-master`
   - Branch: `main`

4. **Configure Environment Variables**
   ```bash
   NODE_ENV=production
   PORT=3000
   
   # Database (Your existing PostgreSQL)
   DB_HOST=192.159.99.184
   DB_PORT=30422
   DB_USER=root
   DB_PASSWORD=ApXJCNH1P6348h2kroSIBK5Q9Vx7v0uD
   DB_NAME=zeabur
   DB_SSL=false
   
   # JWT Secret (Generate a new one)
   JWT_SECRET=<generate-64-char-random-string>
   
   # Encryption Key (Generate a new one)
   ENCRYPTION_KEY=<generate-32-char-random-string>
   
   # CORS (Your domain)
   CORS_ORIGINS=https://your-app.zeabur.app,http://localhost:3001
   ```

5. **Generate Secrets** (Run locally):
   ```bash
   # JWT Secret
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   
   # Encryption Key
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

6. **Deploy**
   - Zeabur will automatically detect `zbpack.json`
   - Build will start automatically
   - Wait 2-3 minutes

7. **Get Your URL**
   - Zeabur will provide: `https://your-app.zeabur.app`
   - Access your management platform!

### Method 2: Full Stack Deploy (Backend + Frontend)

Use the provided `docker-compose.yml` for multi-service deployment.

**Note:** Zeabur currently has limited multi-service support. You may need to:
1. Deploy backend as one service
2. Deploy frontend as another service
3. Configure frontend to point to backend URL

## 🔧 Post-Deployment Configuration

### 1. Update CORS
After deployment, update `CORS_ORIGINS` with your actual Zeabur URL:
```
CORS_ORIGINS=https://your-actual-app.zeabur.app
```

### 2. Test Database Connection
Visit: `https://your-app.zeabur.app/api/health`

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-03T00:00:00.000Z",
  "database": "connected",
  "version": "1.0.0"
}
```

### 3. Login
- URL: `https://your-app.zeabur.app`
- Email: `admin@evilginx.local`
- Password: `admin123`

**⚠️ Change the password immediately!**

## 📁 Project Structure

```
evilginx2-master/
├── zbpack.json                    ← Zeabur configuration
├── management-platform/
│   ├── backend/
│   │   ├── Dockerfile            ← Backend container
│   │   ├── package.json          ← Dependencies
│   │   ├── server.js             ← Entry point
│   │   └── ...
│   ├── frontend/
│   │   ├── Dockerfile            ← Frontend container
│   │   ├── nginx.conf            ← Web server config
│   │   └── ...
│   └── docker-compose.yml        ← Multi-service setup
```

## 🌐 Frontend Access

If you deploy frontend separately:

**Frontend Dockerfile:**
- Location: `management-platform/frontend/Dockerfile`
- Uses: nginx
- Serves: Static files

**Configure API URL:**
Edit `frontend/app.js` or set `API_URL` environment variable to point to your backend.

## 🔒 Security Checklist

After deployment:
- [ ] Change admin password
- [ ] Update JWT_SECRET
- [ ] Update ENCRYPTION_KEY
- [ ] Configure proper CORS_ORIGINS
- [ ] Enable HTTPS (Zeabur does this automatically)
- [ ] Test VPS deployment functionality

## 📊 Database Tables

Your PostgreSQL database already has these tables:
- ✅ `users`
- ✅ `vps_instances`
- ✅ `deployments`
- ✅ `deployment_logs`
- ✅ `evilginx_builds`
- ✅ `github_webhook_settings`
- ✅ `subscriptions`
- ✅ `subscription_plans`

## 🐛 Troubleshooting

### Build Fails
- Check `zbpack.json` is in repository root
- Verify `package.json` has correct dependencies
- Check build logs in Zeabur dashboard

### Database Connection Fails
- Verify DB_HOST is accessible from Zeabur
- Check firewall rules on PostgreSQL server
- Test connection manually

### 500 Errors
- Check environment variables are set
- Verify JWT_SECRET is set
- Check Zeabur runtime logs

## 🚀 Quick Deploy Command

**Option 1: GitHub Integration (Recommended)**
1. Push to GitHub (already done ✅)
2. Connect Zeabur to GitHub
3. Deploy automatically on push

**Option 2: Zeabur CLI**
```bash
# Install Zeabur CLI
npm install -g @zeabur/cli

# Login
zeabur login

# Deploy
zeabur deploy
```

## 📞 Support

If you encounter issues:
1. Check Zeabur runtime logs
2. Verify environment variables
3. Test database connection
4. Check CORS settings

## ✅ Pre-Deployment Checklist

- [x] Repository pushed to GitHub
- [x] zbpack.json configured
- [x] Dockerfile exists
- [x] package.json has all dependencies
- [x] PostgreSQL database running
- [x] Database tables created
- [ ] Environment variables ready to set
- [ ] Secrets generated (JWT, Encryption)

## 🎉 Ready to Deploy!

Your repository is **production-ready** for Zeabur deployment right now!

**Next step:** Go to https://zeabur.com/dashboard and click "New Project"

