
# 🕵️‍♂️ WhereIsIt – Backend Server

A **Node.js + Express + MongoDB** backend for the **WhereIsIt** platform — a lost & found item management system with Firebase authentication, JWT-based sessions, and secure CRUD APIs.  

It handles user registration, authentication, lost/found posts, and recovery tracking with MongoDB as the database and Firebase Admin SDK for token verification.

---

## 🚀 Tech Stack

| Category | Technology |
|----------|------------|
| Runtime | Node.js |
| Framework | Express.js |
| Database | MongoDB (Native Driver) |
| Authentication | Firebase Admin SDK, JWT, Bcrypt |
| File Handling | Multer |
| Environment | dotenv |
| Utilities | CORS, Cookie Parser |

---

## 📂 Project Structure

```
server/
├── index.js
├── firebase-service-account.json
├── package.json
├── .env
└── README.md
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory:

```bash
PORT=5000
MONGO_URI=mongodb+srv://<your-db-url>
JWT_SECRET=yourSuperSecretKey
NODE_ENV=development
```

> ⚠️ Keep `firebase-service-account.json` private — **never push it to GitHub**.

---

## 🧠 Core Features

✅ **User Authentication**

* Firebase login (Google / social auth supported)
* Email-password login & registration
* Secure password hashing with bcryptjs
* JWT-based cookie sessions

✅ **Lost & Found Item Management**

* Post lost or found items
* Edit, delete, or update item status
* Filter items by type, category, location, or keyword

✅ **Item Recovery Flow**

* Record item recovery
* Prevent users from recovering their own items
* Store recovery details (date, location, notes)

✅ **User Statistics**

* Track number of items posted, found, and recovered

✅ **Protected Routes**

* JWT & Firebase token verification middleware
* Route-level protection for user data & posts

---

## 🛠️ Installation & Setup

### 1️⃣ Clone the repository

```bash
git clone https://github.com/<your-username>/whereisit-server.git
cd whereisit-server
```

### 2️⃣ Install dependencies

```bash
npm install
```

### 3️⃣ Setup environment

Create `.env` and `firebase-service-account.json` as described above.

### 4️⃣ Run the server

```bash
npm start
```

or for development:

```bash
nodemon index.js
```

---

## 🔗 API Endpoints Overview

### 🔒 Auth Routes

| Method | Endpoint                    | Description                            |
| ------ | --------------------------- | -------------------------------------- |
| `POST` | `/api/users/register`       | Register a new user                    |
| `POST` | `/api/users/login`          | Login with email & password            |
| `POST` | `/api/users/firebase-login` | Login with Firebase ID token           |
| `POST` | `/api/users/logout`         | Logout and clear cookie                |
| `GET`  | `/api/users/profile`        | Get current user profile *(protected)* |

---

### 📦 Item Routes

| Method   | Endpoint                  | Description                                  |
| -------- | ------------------------- | -------------------------------------------- |
| `POST`   | `/api/items`              | Add a new lost/found item *(protected)*      |
| `GET`    | `/api/items`              | Get all items (supports filters)             |
| `GET`    | `/api/items/:id`          | Get a specific item                          |
| `PUT`    | `/api/items/:id`          | Update an item *(protected)*                 |
| `DELETE` | `/api/items/:id`          | Delete an item *(protected)*                 |
| `GET`    | `/api/items/user/:userId` | Get all items posted by a user *(protected)* |

---

### 🔁 Recovery Routes

| Method | Endpoint                 | Description                                       |
| ------ | ------------------------ | ------------------------------------------------- |
| `POST` | `/api/items/:id/recover` | Report item recovery *(protected)*                |
| `GET`  | `/api/recoveries`        | Get all recoveries for current user *(protected)* |

---

### 📊 User Stats

| Method | Endpoint                   | Description                         |
| ------ | -------------------------- | ----------------------------------- |
| `GET`  | `/api/users/:userId/stats` | Fetch user statistics *(protected)* |

---

## 🔐 Middleware Highlights

* **`protect`** → Verifies Firebase or JWT tokens, attaches user to `req.user`
* **`validateUserData`** → Validates user input during registration
* **`validateItemData`** → Ensures correct item structure before saving

---

## 💾 Database Collections

| Collection   | Purpose                                |
| ------------ | -------------------------------------- |
| `users`      | Stores user data & authentication info |
| `items`      | Stores lost/found item details         |
| `recoveries` | Tracks item recovery actions           |

---

## 🌐 CORS Configuration

```js
origin: ["https://simple-firebase-auth-9089a.web.app"]
```

> Add your frontend URL here when deploying.

---

## 🧪 Example Request (Create Item)

```bash
POST /api/items
Headers:
  Authorization: Bearer <firebase_or_jwt_token>
Body (JSON):
{
  "postType": "lost",
  "thumbnail": "https://i.imgur.com/item.png",
  "title": "Lost Wallet",
  "description": "Brown leather wallet",
  "category": "Accessories",
  "location": "Mirpur 10",
  "date": "2025-10-20"
}
```

Response:

```json
{
  "message": "Item added successfully",
  "itemId": "6717a8b2d33b9c00e1a2b123"
}
```

---

## 🧰 Scripts

| Command     | Description           |
| ----------- | --------------------- |
| `npm start` | Run the server        |
| `npm test`  | Placeholder for tests |

---

## 💡 Future Improvements

* Add image upload support (Firebase Storage / Cloudinary)
* Real-time notifications via WebSockets
* Admin dashboard for item management
* Integration tests using Jest + Supertest

---

## 👨‍💻 Author

**Shahid Hasan Shuvo**
📍 Dhaka, Bangladesh
💼 [GitHub: shahid-hasan-shuvo](https://github.com/shahid-hasan-shuvo)
📧 [mrshanshuvo@gmail.com](mailto:mrshanshuvo@gmail.com)

---

## 🧾 License

This project is licensed under the **ISC License** — free to use and modify for educational or personal projects.
```
