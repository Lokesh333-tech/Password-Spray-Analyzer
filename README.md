# Password Spray Analyzer

**Intelligent Authentication Threat Detection** powered by Design and Analysis of Algorithms (DAA).

Password Spray Analyzer is a full-stack defensive cybersecurity platform that ingests authentication CSV logs, sorts and indexes records using explicit DAA implementations in Python, detects password-spraying campaigns via a configurable Sliding Window engine, prioritizes threats greedily, explores IP-to-account relationships via Bipartite Graph BFS, and generates downloadable PDF and CSV security reports.

---

## Architecture Overview

- **Frontend (`src/`)**: React 19, Vite, TypeScript, Tailwind CSS v4 (dual theme: Bright White Light Mode & Reddish Black Dark Mode), React Router, Recharts, Cytoscape.js, and Lucide React.
- **Backend (`backend/`)**: Modular Python REST API (`backend/app.py` with Flask & Flask-CORS, plus `backend/stdlib_server.py` zero-dependency Python 3.11 HTTP fallback sharing identical handlers), SQLite (`backend/database/schema.sql`), and pure-Python DAA modules (`backend/algorithms/`).
- **Unified Runtime (`server.ts`)**: Express server on port `3000` serving the React application and forwarding `/api/*` requests directly to the Python backend (`127.0.0.1:5001`).

### Implemented DAA Modules (`backend/algorithms/`)

1. **Merge Sort (`merge_sort.py`)** — Explicit stable divide-and-conquer chronological sorting (`O(n log n)` time, `O(n)` auxiliary space).
2. **Hash Table (`hash_table.py`)** — Custom FNV-1a 32-bit hash table with separate chaining and dynamic resizing for source-IP grouping (`O(1)` average lookup, `O(n)` worst-case).
3. **Binary Search (`binary_search.py`)** — Explicit `lower_bound` and `upper_bound` on Merge-Sorted timestamps (`O(log n + k)`).
4. **Sliding Window (`sliding_window.py`)** — Two-pointer window across per-IP chronological events tracking distinct failed usernames inside configurable windows (default 10 minutes, `>= 8` accounts) and detecting `success-after-failure` compromise patterns (`O(n)` per sorted IP stream).
5. **Bipartite Graph & BFS (`graph_bfs.py`)** — Undirected bipartite adjacency graph (`source_ip` <-> `username`) with FIFO queue Breadth-First Search (`O(V + E)`).
6. **Greedy Threat Prioritizer (`greedy_prioritizer.py`)** — Deterministic explainable 0–100 heuristic scoring across 5 weighted dimensions and greedy priority ranking (`Low` 0–29, `Medium` 30–59, `High` 60–79, `Critical` 80–100).

---

## SQLite Database Schema (`backend/database/schema.sql`)

Initialized automatically via `backend/database/db.py` (`init_db()`):

1. `datasets`
2. `authentication_logs` (indexed on `(dataset_id, epoch_ts)`, `(dataset_id, source_ip)`, `(dataset_id, username)`, `(dataset_id, status)`)
3. `detected_threats`
4. `targeted_accounts`
5. `analysis_results`
6. `algorithm_metrics`
7. `application_settings`

---

## Local Installation & Execution

### Prerequisites

- Node.js `>= 20`
- Python `>= 3.11`

### 1. Install Dependencies

```bash
npm install
pip install -r backend/requirements.txt
```

### 2. Initialize Database & Sample Dataset (Optional — auto-initialized on boot)

```bash
python3 -c "from backend.database.db import init_db; init_db()"
python3 backend/sample_data/generate_sample.py
```

### 3. Run Full-Stack Application

Option A — Unified Express + Python server on port `3000`:

```bash
npm run dev
```

Option B — Run Flask backend directly alongside Vite:

```bash
python3 backend/app.py
# In a second terminal:
npm run dev
```

### 4. Automated Tests

```bash
python3 -m unittest discover -s backend/tests -v
```

### 5. Production Build & Deployment

```bash
npm run build
NODE_ENV=production npm start
```
