# Step-by-Step: Upload Project to GitHub

Do these steps in order.

---

## Step 1: Open GitHub and sign in

1. Go to **https://github.com** in your browser.
2. Sign in to your account (or create one if you don’t have it).

---

## Step 2: Create a new repository

1. Click the **+** icon at the top right.
2. Click **New repository**.
3. Fill in:
   - **Repository name:** e.g. `url-intrusion-detection-system` (you can choose another name).
   - **Description:** optional, e.g. `URL-based Intrusion Detection System - Mini Project`.
   - Choose **Public**.
   - **Do not** tick “Add a README file”, “Add .gitignore”, or “Choose a license”.
4. Click **Create repository**.

---

## Step 3: Copy your repository URL

On the new repo page you’ll see a URL like:

`https://github.com/YOUR_USERNAME/url-intrusion-detection-system.git`

Copy this URL. You will use it in Step 5.

---

## Step 4: Open terminal in your project folder

1. Open **PowerShell** or **Command Prompt**.
2. Go to your project folder:

```powershell
cd "C:\Users\Dell\OneDrive\Desktop\Sem 1 Project"
```

---

## Step 5: Connect your folder to GitHub and push

Run these commands **one by one**. Replace `PASTE_YOUR_REPO_URL_HERE` with the URL you copied in Step 3.

**5a. Add the GitHub repo as “origin”:**
```powershell
git remote add origin PASTE_YOUR_REPO_URL_HERE
```
Example:
```powershell
git remote add origin https://github.com/vanshshah/url-intrusion-detection-system.git
```

**5b. Rename the branch to main:**
```powershell
git branch -M main
```

**5c. Push your code to GitHub:**
```powershell
git push -u origin main
```

---

## Step 6: Sign in when asked

- If a browser or login window opens, sign in with your GitHub account.
- If it asks for **username and password:**  
  - Username = your GitHub username  
  - Password = use a **Personal Access Token**, not your GitHub password.  
  - To create a token: GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Generate new token**. Give it “repo” scope and use it as the password.

---

## Step 7: Check on GitHub

1. Refresh your repository page on GitHub.
2. You should see all your project files (backend, frontend, README, etc.).

---

## Quick checklist

- [ ] Step 1: Signed in at github.com  
- [ ] Step 2: Created new repo (no README/gitignore)  
- [ ] Step 3: Copied repo URL  
- [ ] Step 4: Opened terminal in project folder  
- [ ] Step 5a: `git remote add origin YOUR_URL`  
- [ ] Step 5b: `git branch -M main`  
- [ ] Step 5c: `git push -u origin main`  
- [ ] Step 6: Signed in / used token if asked  
- [ ] Step 7: Saw files on GitHub  

---

## If something goes wrong

- **“remote origin already exists”**  
  Run: `git remote remove origin`  
  Then run Step 5a again with the correct URL.

- **“failed to push” / “Authentication failed”**  
  Use a Personal Access Token as the password (see Step 6).

- **“branch ‘main’ doesn’t exist”**  
  Your branch might be `master`. Run: `git push -u origin master` instead of 5b and 5c.
