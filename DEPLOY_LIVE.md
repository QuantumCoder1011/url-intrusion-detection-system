# How to Publish and Make the App Live

Your app has two parts: **Backend (Flask)** and **Frontend (React)**. Deploy both so anyone can use it.

---

## Option A: Render (Backend) + Vercel (Frontend) – Free

### Part 1: Deploy Backend on Render

1. Go to **https://render.com** and sign up (or sign in with GitHub).
2. Click **New +** → **Web Service**.
3. Connect your GitHub account if needed, then select the repo **url-intrusion-detection-system**.
4. Configure:
   - **Name:** e.g. `url-ids-api`
   - **Root Directory:** leave empty or set to `backend`
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app` (or leave blank if you set Root Directory to `backend`; then use `cd backend && gunicorn app:app` or set **Root Directory** to `backend` and **Start Command** to `gunicorn app:app`)
   - If **Root Directory** is `backend`, use **Start Command:** `gunicorn app:app`
5. Click **Create Web Service**.
6. Wait for the first deploy to finish. Copy your backend URL, e.g. **https://url-ids-api.onrender.com** (no trailing slash).

---

### Part 2: Deploy Frontend on Vercel

1. Go to **https://vercel.com** and sign up (or sign in with GitHub).
2. Click **Add New…** → **Project**.
3. Import your GitHub repo **url-intrusion-detection-system**.
4. Configure:
   - **Framework Preset:** Vite or Create React App (Vercel usually detects it).
   - **Root Directory:** leave as `.` or set to `frontend` if you want only the frontend.
   - If repo root has both backend and frontend, set **Root Directory** to `frontend`.
   - **Build Command:** `npm run build` (default for React).
   - **Output Directory:** `build` (default for Create React App).
5. **Environment Variables:** Add one:
   - **Name:** `REACT_APP_API_URL`  
   - **Value:** your backend URL from Part 1, e.g. `https://url-ids-api.onrender.com` (no `/api` at the end; the app adds `/api` itself).
6. Click **Deploy**. Wait for the build to finish.
7. Your app will be live at a URL like **https://url-intrusion-detection-system.vercel.app**.

---

### Part 3: Allow Frontend in Backend CORS (if needed)

If the frontend shows “Could not connect to the server” when using the live URL, the backend may be blocking the request. In **backend/app.py** we have `CORS(app)` which allows all origins by default. If you later restrict CORS, add your Vercel URL (e.g. `https://url-intrusion-detection-system.vercel.app`) to the allowed origins. For now, the default is fine.

---

## Option B: Deploy Both on Render

1. **Backend:** Same as Part 1 above (Web Service, Root Directory `backend`, Start Command `gunicorn app:app`).
2. **Frontend:** On Render, click **New +** → **Static Site**.
   - Connect the same repo.
   - **Root Directory:** `frontend`
   - **Build Command:** `npm install && npm run build`
   - **Publish Directory:** `frontend/build`
   - **Environment Variable:** `REACT_APP_API_URL` = your backend URL (e.g. `https://url-ids-api.onrender.com`)
3. Deploy. Render will give you a URL for the static site (your live frontend).

---

## After Deployment

- **Frontend URL** (Vercel or Render): share this so people can open the app.
- **Backend URL**: only needed for the frontend; users don’t type it.
- On Render free tier, the backend may sleep after 15 minutes of no use; the first request after that can be slow (cold start).

---

## Quick Checklist

- [ ] Backend deployed (Render Web Service), URL copied.
- [ ] Frontend deployed (Vercel or Render Static Site).
- [ ] `REACT_APP_API_URL` set to backend URL (no trailing slash).
- [ ] Open frontend URL in browser and test: upload a file, check dashboard.

Your app is live when the frontend URL opens and can load data and upload files using the deployed backend.
