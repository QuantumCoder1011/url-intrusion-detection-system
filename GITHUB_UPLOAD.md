# How to Upload This Project to GitHub

## Step 1: Create a new repository on GitHub

1. Go to **https://github.com** and sign in.
2. Click the **+** (top right) → **New repository**.
3. Fill in:
   - **Repository name:** e.g. `url-intrusion-detection-system` (or any name you like).
   - **Description:** optional, e.g. "URL-based Intrusion Detection System - Mini Project".
   - **Public** (or Private if you prefer).
   - **Do not** check "Add a README" or "Add .gitignore" (we already have them).
4. Click **Create repository**.

---

## Step 2: Push your project from your computer

Open **PowerShell** or **Command Prompt** in your project folder and run:

```bash
cd "C:\Users\Dell\OneDrive\Desktop\Sem 1 Project"

# Initialize git (if not already done)
git init

# Add all files
git add .

# First commit
git commit -m "Initial commit: URL Intrusion Detection System"

# Add your GitHub repo as remote (replace YOUR_USERNAME and YOUR_REPO with your actual repo name)
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git

# Rename branch to main (if GitHub uses main)
git branch -M main

# Push to GitHub
git push -u origin main
```

**Replace:**
- `YOUR_USERNAME` → your GitHub username  
- `YOUR_REPO` → the repository name you chose (e.g. `url-intrusion-detection-system`)

**Example:** If your username is `vanshshah` and repo is `url-ids`:
```bash
git remote add origin https://github.com/vanshshah/url-ids.git
```

---

## Step 3: If Git asks for login

- **HTTPS:** GitHub will ask for username and password. Use a **Personal Access Token** instead of your account password (Settings → Developer settings → Personal access tokens).
- **SSH:** If you use SSH keys, use the SSH URL:  
  `git@github.com:YOUR_USERNAME/YOUR_REPO.git`

---

## Already ran `git init`?

If the project is already a git repo, you only need to add the remote and push:

```bash
cd "C:\Users\Dell\OneDrive\Desktop\Sem 1 Project"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

---

## Quick checklist

- [ ] GitHub account created / logged in  
- [ ] New repository created on GitHub (no README/gitignore)  
- [ ] Git installed on your PC  
- [ ] `git init` and `git add .` and `git commit` done in project folder  
- [ ] `git remote add origin ...` with your repo URL  
- [ ] `git push -u origin main`  

After this, your project will be on GitHub.
