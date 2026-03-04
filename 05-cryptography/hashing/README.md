# 🔒 Hashing Functions

## 📖 Overview
Hashing is a one-way cryptographic function that converts input data of any size into a fixed-length output (hash). Unlike encryption, hashing is irreversible - you cannot retrieve the original data from the hash.

## 🎯 Common Use Cases

### 1. Password Storage
- Store hashes instead of plaintext passwords
- Add salt to prevent rainbow table attacks
- Use slow hashes (bcrypt, Argon2) for passwords

### 2. Data Integrity
- Verify files haven't been tampered with
- Compare hashes before/after transfer
- Detect corruption or unauthorized changes

### 3. Digital Signatures
- Hash the message, then sign the hash
- More efficient than signing entire message

### 4. Blockchain / Merkle Trees
- Link blocks in blockchain
- Verify transaction integrity

## 📊 Hash Algorithm Comparison

| Algorithm | Hash Size | Speed | Security | Use Case |
|-----------|-----------|-------|----------|----------|
| **MD5** | 128 bits | Very Fast | ❌ Broken | Legacy only |
| **SHA-1** | 160 bits | Fast | ❌ Weak | Legacy only |
| **SHA-256** | 256 bits | Moderate | ✅ Secure | General purpose |
| **SHA-3** | 256-512 bits | Moderate | ✅ Secure | Modern applications |
| **bcrypt** | Variable | Slow | ✅ Secure | Password hashing |
| **Argon2** | Variable | Slow | ✅✅ Very Secure | Password hashing (winner of PHC) |

## ⚠️ Security Warnings

- **Never use MD5 or SHA-1** for security (collision attacks)
- **Always use salt** for password hashing
- **Use key derivation functions** (PBKDF2, bcrypt, Argon2) for passwords
- **Hash functions don't need keys** - if it needs a key, it's a MAC

## 💡 Best Practices

1. **For file integrity**: SHA-256 or SHA-3
2. **For passwords**: bcrypt, Argon2, or PBKDF2
3. **Add salt**: Unique per password
4. **Use pepper**: Additional secret stored separately
5. **Work factor**: Make it computationally expensive
