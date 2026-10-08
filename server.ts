import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const PYTHON_PORT = Number(process.env.AGENTSHIELD_GATEWAY_PORT || 18420);
const PYTHON_HOST = '127.0.0.1';

let pythonProc: ChildProcess | null = null;

function resolveWritableDbPath(): string {
  if (process.env.AGENTSHIELD_DB_PATH) return process.env.AGENTSHIELD_DB_PATH;
  try {
    fs.accessSync(__dirname, fs.constants.W_OK);
    return path.join(__dirname, 'agentshield.db');
  } catch {
    return '/tmp/agentshield.db';
  }
}

function verifyGatewayHealth(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(`http://${PYTHON_HOST}:${PYTHON_PORT}/health`, (res) => {
      if (res.statusCode !== 200) {
        resolve(false);
        return;
      }
      let raw = '';
      res.on('data', (chunk) => {
        raw += chunk;
      });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(raw);
          resolve(parsed && parsed.service === 'AgentShield Runtime Security Gateway');
        } catch {
          resolve(false);
        }
      });
    });
    req.on('error', () => resolve(false));
    req.end();
  });
}

function startPythonBackend(): Promise<void> {
  return new Promise((resolve) => {
    verifyGatewayHealth().then((alreadyUp) => {
      if (alreadyUp) {
        resolve();
        return;
      }
      spawnProcess();
    });

    const spawnProcess = () => {
      try {
        pythonProc = spawn('python3', ['-u', path.join(__dirname, 'backend', 'main.py')], {
          cwd: __dirname,
          env: {
            ...process.env,
            BACKEND_HOST: PYTHON_HOST,
            BACKEND_PORT: String(PYTHON_PORT),
            AGENTSHIELD_DB_PATH: resolveWritableDbPath(),
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        });

        pythonProc.on('error', (err) => {
          console.error(`[AgentShield] Failed to spawn python3 process: ${err.message}`);
          resolve();
        });

        pythonProc.stdout?.on('data', (chunk) => {
          process.stdout.write(`[PythonGateway] ${chunk}`);
        });

        pythonProc.stderr?.on('data', (chunk) => {
          process.stderr.write(`[PythonGateway] ${chunk}`);
        });

        pythonProc.on('exit', (code) => {
          console.warn(`[AgentShield] Python gateway exited with code ${code}. Restarting in 1s...`);
          setTimeout(() => {
            startPythonBackend().catch(() => {});
          }, 1000);
        });
      } catch (err) {
        console.error('[AgentShield] Error starting Python backend:', err);
        resolve();
        return;
      }

      // Poll until healthy
      let attempts = 0;
      const poll = () => {
        attempts += 1;
        verifyGatewayHealth().then((healthy) => {
          if (healthy || attempts >= 35) {
            resolve();
          } else {
            setTimeout(poll, 120);
          }
        });
      };
      setTimeout(poll, 120);
    };
  });
}

const API_PREFIXES = [
  '/api',
  '/health',
  '/tool-request',
  '/events',
  '/agents',
  '/capabilities',
  '/context-trust',
  '/behavior',
  '/attack-chain',
  '/blast-radius',
  '/metrics',
  '/replay',
  '/tools',
  '/sessions',
  '/agent',
  '/security-tests',
  '/system',
];

function isGatewayApiRoute(urlPath: string): boolean {
  for (const prefix of API_PREFIXES) {
    if (urlPath === prefix || urlPath.startsWith(`${prefix}/`) || urlPath.startsWith(`${prefix}?`)) {
      return true;
    }
  }
  return false;
}

function proxyToPythonGateway(req: Request, res: Response): void {
  const bodyStr = req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : '';
  const options: http.RequestOptions = {
    hostname: PYTHON_HOST,
    port: PYTHON_PORT,
    path: req.originalUrl,
    method: req.method,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr),
    },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.status(proxyRes.statusCode || 500);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    res.status(502).json({
      error: `AgentShield Python Gateway unavailable: ${err.message}`,
      decision: 'BLOCK',
      fail_closed: true,
    });
  });

  if (bodyStr) {
    proxyReq.write(bodyStr);
  }
  proxyReq.end();
}

export async function createServer() {
  await startPythonBackend();

  const app = express();
  app.use(express.json({ limit: '2mb' }));

  app.use((req: Request, res: Response, next: NextFunction) => {
    if (isGatewayApiRoute(req.originalUrl)) {
      // Only proxy if it's an API call (or Accept: application/json or /api/*)
      if (
        req.originalUrl.startsWith('/api') ||
        req.method !== 'GET' ||
        req.originalUrl.startsWith('/health') ||
        req.originalUrl.startsWith('/tool-request') ||
        req.originalUrl.startsWith('/events') ||
        req.originalUrl.startsWith('/agents') ||
        req.originalUrl.startsWith('/capabilities') ||
        req.originalUrl.startsWith('/context-trust') ||
        req.originalUrl.startsWith('/behavior') ||
        req.originalUrl.startsWith('/attack-chain') ||
        req.originalUrl.startsWith('/blast-radius') ||
        req.originalUrl.startsWith('/metrics') ||
        req.originalUrl.startsWith('/replay') ||
        req.originalUrl.startsWith('/tools') ||
        req.originalUrl.startsWith('/sessions') ||
        req.originalUrl.startsWith('/agent/') ||
        req.originalUrl.startsWith('/security-tests') ||
        req.originalUrl.startsWith('/system/')
      ) {
        return proxyToPythonGateway(req, res);
      }
    }
    next();
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.use((_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return app;
}

if (process.env.VITEST !== 'true') {
  createServer().then((app) => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[AgentShield] Full-Stack SOC Server listening on http://0.0.0.0:${PORT}`);
    });
  });
}
