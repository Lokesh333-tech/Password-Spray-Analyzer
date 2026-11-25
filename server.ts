import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const PYTHON_API_PORT = Number(process.env.PYTHON_API_PORT || 5001);
const PYTHON_API_URL = `http://127.0.0.1:${PYTHON_API_PORT}`;

let pythonProc: ChildProcess | null = null;

function hasFlaskInstalled(): boolean {
  const probe = spawnSync('python3', ['-c', 'import flask, flask_cors'], {
    cwd: __dirname,
    stdio: 'ignore',
  });
  return probe.status === 0;
}

function startPythonBackend(): void {
  const useFlask = hasFlaskInstalled();
  const scriptPath = useFlask
    ? path.join(__dirname, 'backend', 'app.py')
    : path.join(__dirname, 'backend', 'stdlib_server.py');

  const env = {
    ...process.env,
    FLASK_PORT: String(PYTHON_API_PORT),
    PYTHON_API_PORT: String(PYTHON_API_PORT),
    PYTHONPATH: __dirname,
  };

  pythonProc = spawn('python3', [scriptPath], {
    cwd: __dirname,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  pythonProc.stdout?.on('data', (chunk: Buffer) => {
    const text = chunk.toString().trim();
    if (text) console.log(`[python-api] ${text}`);
  });

  pythonProc.stderr?.on('data', (chunk: Buffer) => {
    const text = chunk.toString().trim();
    if (text) console.error(`[python-api] ${text}`);
  });

  pythonProc.on('exit', (code) => {
    console.warn(`[python-api] exited with code ${code ?? 'null'}`);
    pythonProc = null;
  });
}

async function waitForPythonApi(maxAttempts = 25): Promise<void> {
  for (let i = 0; i < maxAttempts; i += 1) {
    try {
      const res = await fetch(`${PYTHON_API_URL}/api/health`);
      if (res.ok) return;
    } catch {
      // Wait for Python process bind
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  console.warn('[python-api] Health check did not respond before timeout.');
}

async function createServer(): Promise<void> {
  startPythonBackend();
  await waitForPythonApi();

  const app = express();

  // Forward all /api/* requests directly to the Python DAA + SQLite backend
  app.use('/api', express.raw({ type: '*/*', limit: '26mb' }), async (req: Request, res: Response) => {
    try {
      const targetUrl = `${PYTHON_API_URL}${req.originalUrl}`;
      const forwardHeaders: Record<string, string> = {};

      if (req.headers['content-type']) {
        forwardHeaders['content-type'] = String(req.headers['content-type']);
      }
      if (req.headers['x-filename']) {
        forwardHeaders['x-filename'] = String(req.headers['x-filename']);
      }

      const hasBody = !['GET', 'HEAD'].includes(req.method.toUpperCase());
      const bodyBuffer = hasBody && Buffer.isBuffer(req.body) ? req.body : undefined;

      const upstream = await fetch(targetUrl, {
        method: req.method,
        headers: forwardHeaders,
        body: bodyBuffer && bodyBuffer.length > 0 ? new Uint8Array(bodyBuffer) : undefined,
      });

      res.status(upstream.status);
      const contentType = upstream.headers.get('content-type');
      if (contentType) res.setHeader('Content-Type', contentType);
      const contentDisp = upstream.headers.get('content-disposition');
      if (contentDisp) res.setHeader('Content-Disposition', contentDisp);

      const arrayBuf = await upstream.arrayBuffer();
      res.send(Buffer.from(arrayBuf));
    } catch (err) {
      console.error('[api-proxy] Error forwarding request:', err);
      res.status(502).json({
        error: 'Python analysis engine is unavailable. Please retry in a moment.',
      });
    }
  });

  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.join(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build artifacts not found. Run npm run build first.');
      }
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Password Spray Analyzer server listening on http://0.0.0.0:${PORT}`);
  });

  const shutdown = () => {
    if (pythonProc) {
      pythonProc.kill('SIGTERM');
    }
    server.close(() => process.exit(0));
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

createServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
