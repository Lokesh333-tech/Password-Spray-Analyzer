FROM node:22-bookworm-slim

# Install Python 3 runtime and pip for Flask + Pandas + ReportLab
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python backend dependencies in an isolated venv
COPY backend/requirements.txt ./backend/requirements.txt
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r backend/requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

# Install Node dependencies and build production frontend
COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

# Persist SQLite data inside /app/backend/data
RUN mkdir -p /app/backend/data

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
