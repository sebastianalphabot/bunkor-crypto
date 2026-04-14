# Bunkor Integration Guide

Complete guide to integrating `@bunkor/crypto` with Bunkor secure storage.

## Configuration

### 1. Initialize Bunkor Client

```typescript
import { BunkorClient } from '@bunkor/crypto';

const bunkorClient = new BunkorClient({
  apiUrl: 'https://api.bunkor.io',  // or your self-hosted instance
  apiToken: 'sk_live_...',           // Your Bunkor API token
  organizationId: 'org_...',         // Your organization ID (optional)
  debug: true,                       // Enable debug logging
  timeout: 30000,                    // Request timeout in ms
  chunkSize: 5 * 1024 * 1024,       // 5MB chunks for upload
});
```

### 2. Environment Variables

Create a `.env` file:

```bash
# Bunkor API Configuration
BUNKOR_API_URL=https://api.bunkor.io
BUNKOR_API_TOKEN=sk_live_xxxxxxxxxxxxx
BUNKOR_ORG_ID=org_xxxxxxxxxxxxx
BUNKOR_DEBUG=true
```

Load in your app:

```typescript
const bunkorClient = new BunkorClient({
  apiUrl: process.env['BUNKOR_API_URL']!,
  apiToken: process.env['BUNKOR_API_TOKEN']!,
  organizationId: process.env['BUNKOR_ORG_ID'],
  debug: process.env['BUNKOR_DEBUG'] === 'true',
});
```

## Upload Encrypted Files

### Basic Upload

```typescript
import { BunkorClient } from '@bunkor/crypto';

const client = new BunkorClient({
  apiUrl: 'https://api.bunkor.io',
  apiToken: 'sk_live_...',
});

// Upload file with encryption
const result = await client.uploadEncrypted(
  file,                    // File or Blob
  'user-password',         // Encryption password
  'AES-256-GCM',          // Algorithm
  file.name               // Optional: custom file name
);

// Store these for later download
console.log('File ID:', result.fileId);
console.log('Salt:', result.salt);
console.log('IV:', result.iv);
```

### Upload with Progress Tracking

```typescript
// Note: Progress is tracked in the UI layer
// BunkorClient.uploadEncrypted handles encryption + network

// For granular control with XMLHttpRequest:
async function uploadWithProgress(file: File, password: string, onProgress: (pct: number) => void) {
  const { encryptedBlob, salt, iv } = await encryptionService.encryptFile({
    file,
    password,
    algorithm: 'AES-256-GCM',
    salt: cryptoService.generateSalt(),
    iv: generateIv(),
  });

  const formData = new FormData();
  formData.append('file', encryptedBlob);
  formData.append('salt', salt);
  formData.append('iv', iv);

  const xhr = new XMLHttpRequest();
  xhr.upload.addEventListener('progress', (e) => {
    if (e.lengthComputable) {
      onProgress(Math.round((e.loaded / e.total) * 100));
    }
  });

  xhr.open('POST', '/api/files/upload');
  xhr.setRequestHeader('Authorization', `Bearer ${token}`);
  xhr.send(formData);
}
```

### Upload with Multiple Algorithm Options

```typescript
import { BunkorClient, ENCRYPTION_DEFAULTS } from '@bunkor/crypto';

const client = new BunkorClient({ apiUrl, apiToken });

// For post-quantum security
const result = await client.uploadEncrypted(
  file,
  password,
  'Kyber-768-AES'  // Post-quantum hybrid
);

// Choose algorithm based on security requirements
const algorithm = highSecurityRequired 
  ? 'Kyber-1024-AES'  // Maximum security
  : 'AES-256-GCM';   // Standard (recommended)

const result = await client.uploadEncrypted(
  file,
  password,
  algorithm
);
```

## Download & Decrypt Files

### Basic Download

```typescript
import { BunkorClient } from '@bunkor/crypto';

const client = new BunkorClient({
  apiUrl: 'https://api.bunkor.io',
  apiToken: 'sk_live_...',
});

// Download and decrypt
const decrypted = await client.downloadDecrypted(
  'file_abc123',      // File ID from upload
  'user-password'     // Must match encryption password
);

// Download to user's device
const url = URL.createObjectURL(decrypted);
const a = document.createElement('a');
a.href = url;
a.download = 'document.pdf';
a.click();
URL.revokeObjectURL(url);
```

### Download with Progress

```typescript
const decrypted = await client.downloadDecrypted(
  'file_abc123',
  'user-password',
  (progress) => {
    console.log(`Downloaded: ${progress}%`);
    // Update UI progress bar
    progressBar.value = progress;
  }
);
```

### Download with Error Handling

```typescript
try {
  const decrypted = await client.downloadDecrypted(
    fileId,
    password
  );
} catch (error) {
  if (error instanceof Error) {
    if (error.message.includes('401')) {
      console.error('Authentication failed - invalid API token');
    } else if (error.message.includes('404')) {
      console.error('File not found');
    } else if (error.message.includes('Decryption failed')) {
      console.error('Wrong password or corrupted file');
    } else {
      console.error('Download failed:', error.message);
    }
  }
}
```

## File Management

### List Files

```typescript
// List all files in your organization
const files = await client.listFiles();

// With pagination
const files = await client.listFiles({
  limit: 50,
  offset: 0,
});

// Display in UI
files.forEach(file => {
  console.log(`${file.fileName} (${formatBytes(file.size)})`);
  console.log(`  Algorithm: ${file.encryptionAlgorithm}`);
  console.log(`  Created: ${new Date(file.createdAt).toLocaleString()}`);
});
```

### Get File Metadata

```typescript
const metadata = await client.getFileMetadata('file_abc123');

console.log('File Name:', metadata.fileName);
console.log('Size:', formatBytes(metadata.size));
console.log('Algorithm:', metadata.encryptionAlgorithm);
console.log('Created:', new Date(metadata.createdAt).toLocaleString());
console.log('Owner:', metadata.ownerId);
```

### Delete File

```typescript
// Permanently delete a file
await client.deleteFile('file_abc123');
console.log('File deleted');
```

### Share File

```typescript
// Share with another user
const { shareId, shareUrl } = await client.shareFile(
  'file_abc123',
  'user@example.com',
  7 * 24 * 60 * 60  // Expire in 7 days (seconds)
);

console.log('Share URL:', shareUrl);
// Send shareUrl to the recipient
```

## Audit & Compliance

### Get Audit Log

```typescript
// View who accessed what, when
const auditLog = await client.getAuditLog('file_abc123');

auditLog.forEach(entry => {
  console.log(`${entry.action} by ${entry.user} at ${entry.timestamp}`);
  console.log(`  IP: ${entry.ipAddress}`);
});
```

### Check API Health

```typescript
const isHealthy = await client.healthCheck();

if (isHealthy) {
  console.log(' Bunkor API is accessible');
} else {
  console.error(' Cannot reach Bunkor API');
}
```

## Angular Integration

### As Angular Service

```typescript
import { Injectable } from '@angular/core';
import { BunkorClient } from '@bunkor/crypto';

@Injectable({
  providedIn: 'root'
})
export class FileEncryptionService {
  private bunkor: BunkorClient;

  constructor() {
    this.bunkor = new BunkorClient({
      apiUrl: 'https://api.bunkor.io',
      apiToken: localStorage.getItem('bunkor_token') || '',
    });
  }

  uploadFile(file: File, password: string) {
    return this.bunkor.uploadEncrypted(file, password, 'AES-256-GCM');
  }

  downloadFile(fileId: string, password: string, onProgress?: (pct: number) => void) {
    return this.bunkor.downloadDecrypted(fileId, password, onProgress);
  }

  listFiles() {
    return this.bunkor.listFiles({ limit: 100 });
  }

  deleteFile(fileId: string) {
    return this.bunkor.deleteFile(fileId);
  }
}
```

### In Components

```typescript
import { Component, inject } from '@angular/core';
import { FileEncryptionService } from './services/file-encryption.service';

@Component({
  selector: 'app-file-manager',
  template: `
    <input type="file" (change)="onFileSelect($event)" />
    <input type="password" placeholder="Encryption password" [(ngModel)]="password" />
    <button (click)="uploadFile()">Upload Encrypted</button>
    
    <div *ngFor="let file of files">
      {{ file.fileName }}
      <button (click)="downloadFile(file.fileId)">Download</button>
      <button (click)="deleteFile(file.fileId)">Delete</button>
    </div>
  `,
})
export class FileManagerComponent {
  private fileService = inject(FileEncryptionService);

  selectedFile: File | null = null;
  password = '';
  files: any[] = [];

  ngOnInit() {
    this.loadFiles();
  }

  async loadFiles() {
    this.files = await this.fileService.listFiles();
  }

  onFileSelect(event: Event) {
    this.selectedFile = (event.target as HTMLInputElement).files?.[0] || null;
  }

  async uploadFile() {
    if (!this.selectedFile || !this.password) return;

    try {
      const result = await this.fileService.uploadFile(this.selectedFile, this.password);
      console.log('Uploaded:', result.fileId);
      await this.loadFiles();
    } catch (error) {
      console.error('Upload failed:', error);
    }
  }

  async downloadFile(fileId: string) {
    try {
      const blob = await this.fileService.downloadFile(fileId, this.password);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'file';
      a.click();
    } catch (error) {
      console.error('Download failed:', error);
    }
  }

  async deleteFile(fileId: string) {
    if (confirm('Delete this file?')) {
      await this.fileService.deleteFile(fileId);
      await this.loadFiles();
    }
  }
}
```

## Error Handling

```typescript
import { BunkorClient } from '@bunkor/crypto';

const client = new BunkorClient({ apiUrl, apiToken });

try {
  const result = await client.uploadEncrypted(file, password);
} catch (error) {
  if (error instanceof Error) {
    // Handle specific errors
    if (error.message.includes('401')) {
      // Unauthorized - invalid token
    } else if (error.message.includes('413')) {
      // Payload too large
    } else if (error.message.includes('429')) {
      // Rate limited
    } else if (error.message.includes('Decryption failed')) {
      // Wrong password
    } else {
      // Generic error
      console.error('Error:', error.message);
    }
  }
}
```

## Best Practices

### 1. Password Management

```typescript
import { validatePassword, calculatePasswordStrength } from '@bunkor/crypto';

// Validate before encryption
const validation = validatePassword(userPassword);
if (!validation.valid) {
  console.error(validation.message);
  return;
}

// Show password strength indicator
const strength = calculatePasswordStrength(userPassword);
console.log(`Password strength: ${strength}%`);
```

### 2. Secure Storage of File IDs

```typescript
//  DON'T: Store sensitive data in localStorage
localStorage.setItem('fileId', fileId);

//  DO: Store in a secure, encrypted database
// or in-memory with session storage
sessionStorage.setItem('tempFileId', fileId);

//  DO: Use private class properties
private fileIds: string[] = [];
```

### 3. Clean Up Resources

```typescript
import { clearSensitiveData } from '@bunkor/crypto';

// Clear sensitive data when done
const password = new TextEncoder().encode('password');
clearSensitiveData(password);

// Revoke object URLs
URL.revokeObjectURL(url);
```

### 4. Progress Tracking

```typescript
async uploadFile(file: File, password: string) {
  const progressElement = document.getElementById('upload-progress');
  
  const result = await this.bunkor.uploadEncrypted(
    file,
    password,
    'AES-256-GCM'
  );

  // Note: BunkorClient handles encryption + network
  // For detailed progress, implement chunked upload
}
```

## API Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/files/upload` | POST | Upload encrypted file |
| `/v1/files/:fileId/download` | GET | Download encrypted file |
| `/v1/files/:fileId` | GET | Get file metadata |
| `/v1/files` | GET | List all files |
| `/v1/files/:fileId` | DELETE | Delete file |
| `/v1/files/:fileId/share` | POST | Share with user |
| `/v1/files/:fileId/audit` | GET | Get audit log |
| `/v1/health` | GET | Health check |

## Troubleshooting

### Upload Fails with 401

```
Solution: Check API token
- Verify token in environment variables
- Ensure token hasn't expired
- Check organization ID is correct
```

### Download Returns "Decryption failed"

```
Solution: Password mismatch
- Verify you're using the correct password
- Ensure file wasn't corrupted during transfer
- Check algorithm matches what was used for encryption
```

### Slow Upload/Download

```
Solution: Optimize chunk size
- Adjust chunkSize in BunkorConfig (default 5MB)
- Consider network conditions
- Monitor concurrent uploads
```

---

For more details on encryption algorithms, see [ALGORITHMS.md](ALGORITHMS.md)
