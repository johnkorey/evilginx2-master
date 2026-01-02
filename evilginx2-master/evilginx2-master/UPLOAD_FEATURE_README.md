# 🚀 Evilginx Build Upload System

## Overview

This new feature allows **admins to upload** Evilginx source code builds to the management platform, and **users can deploy** those builds directly to their VPS instances - **no GitHub required**!

## ✅ What's Been Completed

### 1. Database Table
- Created `evilginx_builds` table to store uploaded builds
- Tracks version, file info, hash, and active status
- Run migration: `node add-builds-table.js` ✅ **DONE**

### 2. Backend API Routes (`routes/upload.js`)
- **POST `/api/upload/evilginx-build`** - Admin uploads a build (ZIP/tar.gz)
- **GET `/api/upload/evilginx-builds`** - List all uploads
- **GET `/api/upload/evilginx-builds/active`** - Get active build
- **POST `/api/upload/evilginx-builds/:id/activate`** - Set active build
- **DELETE `/api/upload/evilginx-builds/:id`** - Delete a build

### 3. File Storage
- Uploads stored in `management-platform/backend/uploads/evilginx-builds/`
- SHA-256 hash verification
- Max file size: 500MB

### 4. Dependencies
- Installed `multer` for file uploads ✅ **DONE**

## 🔧 What Needs to Be Done

### 1. Update SSH Service (`services/ssh.js`)
Currently, deployments use `git clone`. Need to modify to:

```javascript
async deploy(vpsId, deploymentId) {
    // Instead of git clone:
    // 1. Get active build from database
    // 2. Upload build file to VPS via SFTP
    // 3. Extract on VPS
    // 4. Build and install
}
```

**Key changes needed:**
- Replace git clone logic (lines ~473-484) with file upload
- Use `ssh2` SFTP to transfer the file
- Extract using `tar -xzf` or `unzip` on VPS

### 2. Update `server.js`
Add the upload route (if not already added):

```javascript
const uploadRoutes = require('./routes/upload');
app.use('/api/upload', uploadRoutes);
```

### 3. Create Admin UI
Add to the admin dashboard (`admin/index.html` and `admin/app.js`):

```html
<!-- New section in admin panel -->
<section id="builds-section">
    <h2>Evilginx Builds</h2>
    
    <!-- Upload form -->
    <form id="upload-build-form">
        <input type="file" name="file" accept=".zip,.tar,.gz,.tgz" required>
        <input type="text" name="version" placeholder="Version (e.g., 3.3.0)" required>
        <textarea name="description" placeholder="Release notes..."></textarea>
        <button type="submit">Upload Build</button>
    </form>
    
    <!-- List of builds -->
    <table id="builds-table">
        <!-- List builds with activate/delete buttons -->
    </table>
</section>
```

**JavaScript needed in `app.js`:**

```javascript
async uploadBuild(formData) {
    const response = await fetch('/api/upload/evilginx-build', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${this.token}`
        },
        body: formData
    });
    return await response.json();
}

async loadBuilds() {
    const result = await this.apiRequest('/upload/evilginx-builds');
    // Display builds in table
}
```

## 📦 How to Package Evilginx for Upload

### Option 1: ZIP the repository
```bash
cd /path/to/evilginx2-master
zip -r evilginx-3.3.0.zip . -x "*.git*" -x "*node_modules*"
```

### Option 2: TAR.GZ (preferred for Linux)
```bash
tar -czf evilginx-3.3.0.tar.gz \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='*.exe' \
    .
```

## 🔄 Deployment Flow

1. **Admin uploads** a build file (ZIP/tar.gz) via the dashboard
2. **Platform stores** the file and marks it as active
3. **User clicks "Deploy"** on their VPS instance
4. **Platform:**
   - Gets the active build from the database
   - Uploads it to the VPS via SFTP
   - Extracts: `tar -xzf evilginx.tar.gz -C /opt/evilginx/src`
   - Builds: `cd /opt/evilginx/src && go build`
   - Installs and restarts

## 🎯 Benefits

✅ **No GitHub dependency** - VPS doesn't need internet access to GitHub  
✅ **Faster deployments** - Local file transfer instead of git clone  
✅ **Version control** - Admin controls what version gets deployed  
✅ **Offline capable** - Works in restricted environments  
✅ **Bandwidth efficient** - Only transfer what's needed

## 🔐 Security

- Admin-only upload (requireAdmin middleware)
- SHA-256 hash verification
- File type validation (.zip, .tar.gz only)
- Stored outside web root
- No direct file access via HTTP

## 📝 Database Schema

```sql
CREATE TABLE evilginx_builds (
    id UUID PRIMARY KEY,
    version VARCHAR(100) NOT NULL,
    description TEXT,
    filename VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    is_active BOOLEAN DEFAULT false,
    uploaded_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🚀 Next Steps

1. ✅ Database table created
2. ✅ API routes created
3. ✅ Multer installed
4. ⏳ Modify SSH service to use uploaded files
5. ⏳ Create admin UI for uploads
6. ⏳ Test full deployment flow

## 📞 Notes

- Current active build is stored in the database with `is_active = true`
- Only one build can be active at a time
- Old builds can be deleted after confirming they're not needed
- File uploads are stored in: `backend/uploads/evilginx-builds/`

