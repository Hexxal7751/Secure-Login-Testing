# 🔐 Security Portal with Mandatory Passkeys

A **stunning, ultra-secure** authentication system featuring **mandatory passkeys** (WebAuthn) combined with TOTP-based 2FA for maximum security. Now with a **beautiful, modern glassmorphism UI** and smooth animations!

![Security Portal](https://img.shields.io/badge/Security-Maximum-brightgreen)
![Passkeys](https://img.shields.io/badge/Passkeys-Mandatory-blue)
![UI](https://img.shields.io/badge/UI-Modern-purple)
![Animations](https://img.shields.io/badge/Animations-Smooth-orange)

## ✨ Features

### 🔐 **Mandatory Passkeys** - All users must use passkeys for authentication
### 📱 **TOTP 2FA** - Required before passkey setup  
### 🛡️ **Multi-Layer Security** - Password + 2FA + Passkey authentication
### 🎨 **Modern Glassmorphism UI** - Beautiful, responsive design with smooth animations
### ⚡ **Rate Limiting** - Advanced protection against brute force attacks
### 🔒 **CSRF Protection** - Cross-site request forgery prevention
### 🌙 **Dark Mode Support** - Automatic theme detection and toggle
### 📱 **Mobile Responsive** - Perfect on all devices
### ♿ **Accessibility** - WCAG compliant with reduced motion support
### 🔐 **Row-Level Security (RLS)** - Database-level security with automatic context management
### 🛡️ **Content Security Policy** - Comprehensive protection against XSS attacks
### 📊 **Security Logging** - Advanced logging system for security events
### 🧪 **Input Validation** - Robust validation and sanitization of all user inputs

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Environment Setup

Create a `.env` file with the following variables:

```env
# Flask Configuration
FLASK_PASS=your-super-secret-flask-key-here
FLASK_ENV=development

# Database Configuration
SUPABASE_URL=postgresql://username:password@host:port/database

# WebAuthn Configuration (for production)
RP_ID=yourdomain.com
ORIGIN=https://yourdomain.com

# For local development, use:
# RP_ID=localhost
# ORIGIN=http://localhost:5000
```

### 3. Run the Application

```bash
python app.py
```

Visit `http://localhost:5000` to access the application.

## 🎨 **New Modern UI Features**

### **Glassmorphism Design**
- Beautiful frosted glass effects
- Smooth backdrop blur
- Subtle transparency layers
- Modern gradient backgrounds

### **Smooth Animations**
- Floating particles background
- Card entrance animations
- Button hover effects with ripple
- Loading spinners with blur
- Pulse effects on QR codes

### **Interactive Elements**
- Hover effects on all buttons
- Form input focus animations
- Real-time username availability checking
- Emergency logout keyboard shortcuts
- Theme toggle with persistence

### **Visual Enhancements**
- Gradient text effects
- Modern color palette
- Responsive grid layouts
- Professional typography
- Icon integration

## 🔐 Mandatory Authentication Flow

### For New Users

1. **Register** with username/password
2. **Login** with username/password  
3. **Complete 2FA** setup with TOTP
4. **Setup Passkey** (mandatory requirement)
5. **Access Dashboard** (only after all steps complete)

### For Existing Users

1. **Login** with username/password

## 🛡️ Enterprise-Grade Security

This application implements comprehensive security measures for production-ready deployment:

### 🔒 **Authentication & Authorization**
- Multi-factor authentication (TOTP and WebAuthn/Passkeys)
- Row-Level Security (RLS) for database access control
- Session management with secure cookies
- Account lockout after multiple failed attempts

### 🔐 **Data Protection**
- TLS/SSL encryption for all data transmissions
- Secure password hashing using bcrypt
- Database encryption for sensitive data
- Automatic RLS context management

### 🛡️ **Attack Prevention**
- Content Security Policy (CSP) against XSS attacks
- Rate limiting and IP-based blocking
- Input validation and sanitization
- Protection against SQL injection, CSRF, and other common attacks

### 📊 **Monitoring & Logging**
- Comprehensive security event logging
- Standardized log format for security events
- Suspicious activity monitoring

For detailed security information, see [SECURITY.md](./SECURITY.md)
2. **Verify 2FA** with TOTP code
3. **Setup Passkey** (if not already done)
4. **Access Dashboard**

### Security Requirements

- **Passwords** - Traditional authentication (required for initial access)
- **TOTP 2FA** - Time-based one-time passwords (required before passkey setup)
- **Passkeys** - WebAuthn-based authentication (mandatory for all users)

## 🛡️ Security Features

### Multi-Layer Authentication
- **Layer 1**: Username/Password authentication
- **Layer 2**: TOTP-based 2FA verification
- **Layer 3**: Passkey authentication (mandatory)

### Security Headers
- Content Security Policy (CSP) with nonces
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Referrer Policy

### Session Security
- Session regeneration on login
- CSRF token protection
- Secure cookie settings
- Session timeout (30 minutes)

### Rate Limiting
- Login: 10 requests per minute
- Registration: 5 requests per minute
- TOTP setup: 5 requests per minute

## 📱 Browser Support

Passkeys work on:
- **Chrome** 67+ (Desktop & Mobile)
- **Safari** 13+ (Desktop & Mobile)
- **Firefox** 60+ (Desktop)
- **Edge** 18+ (Desktop)

## 🔧 Configuration

### Production Deployment

1. Set `FLASK_ENV=production`
2. Configure `RP_ID` to your domain
3. Set `ORIGIN` to your HTTPS URL
4. Use a strong `FLASK_PASS`
5. Ensure HTTPS is enabled

### Database

The application creates these tables:
- `users` - User accounts and authentication info
- `passkeys` - WebAuthn credentials

## 🚨 Security Notes

- **Passkeys are mandatory** - Users cannot access the dashboard without setting up passkeys
- **Multi-factor authentication** - Users must complete both 2FA and passkey setup
- **No password-only access** - Traditional passwords are only used for initial authentication
- **Phishing-resistant** - Passkeys are bound to your domain and cannot be phished
- **Device security** - Uses device biometrics, PIN, or other security measures

## 🔄 User Flow

```
Registration → Login → 2FA Setup → 2FA Verification → Passkey Setup → Dashboard
     ↓              ↓           ↓              ↓              ↓           ↓
  Username/    Username/    TOTP QR     6-digit      Device      Full
  Password     Password     Code        Code         Security    Access
```

## 🎯 **UI/UX Highlights**

### **Modern Design System**
- Inter font family for clean typography
- CSS custom properties for consistent theming
- Glassmorphism effects throughout
- Smooth transitions and micro-interactions

### **Enhanced User Experience**
- Real-time feedback on all actions
- Intuitive navigation flow
- Clear visual hierarchy
- Accessible color contrast
- Mobile-first responsive design

### **Performance Optimizations**
- Efficient CSS animations
- Optimized loading states
- Reduced motion support
- Progressive enhancement

## 📄 License

This project is for educational and demonstration purposes.

---

**🔐 Maximum Security by Design - Passkeys Required** 

**🎨 Beautiful Modern UI - Glassmorphism Design**