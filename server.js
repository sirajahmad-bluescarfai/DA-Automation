const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const os      = require('os');
const multer  = require('multer');
const { Client } = require('ssh2');

const app      = express();
const PORT     = 3030;
const PCAP_DIR = path.join(__dirname, 'PCAPs');
const upload   = multer({ dest: os.tmpdir() });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

/* ── SSH session store ── */
const sessions = new Map();

// Evict sessions older than 30 min every 5 min
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [id, sess] of sessions) {
    if (sess.createdAt < cutoff) {
      try { sess.conn.destroy(); } catch (_) {}
      sessions.delete(id);
    }
  }
}, 5 * 60 * 1000);

function getSession(sessionId) {
  return sessions.get(sessionId) || null;
}

/* ── PCAP file tree ── */
function buildTree(dirPath) {
  const name = path.basename(dirPath);
  const node = { name, type: 'directory', children: [] };

  const items = fs.readdirSync(dirPath, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })
  );

  for (const item of items) {
    const fullPath = path.join(dirPath, item.name);
    if (item.isDirectory()) {
      const child = buildTree(fullPath);
      if (child.children.length > 0) node.children.push(child);
    } else if (item.name.toLowerCase().endsWith('.pcap')) {
      const relativePath = path.relative(__dirname, fullPath).replace(/\\/g, '/');
      node.children.push({ name: item.name, type: 'file', path: relativePath });
    }
  }
  return node;
}

app.get('/api/files', (req, res) => {
  try { res.json(buildTree(PCAP_DIR)); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── PCAP replay ── */
app.post('/api/replay', (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0)
    return res.status(400).json({ error: 'No files provided' });
  console.log(`[Replay] ${files.length} files requested`);
  files.forEach(f => console.log('  -', f));
  res.json({ status: 'ok', count: files.length, files });
});

/* ── Replay: SSH service-check helper ── */
function sshCheckService(ip, username, password, serviceName) {
  return new Promise((resolve) => {
    const conn = new Client();
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.destroy(); } catch (_) {}
      resolve(result);
    };

    const timer = setTimeout(() =>
      finish({ up: false, error: 'Connection timed out after 10 seconds.' }), 10000);

    conn.on('ready', () => {
      conn.exec(`systemctl is-active "${serviceName}"`, (err, stream) => {
        if (err) { finish({ up: false, error: 'exec error: ' + err.message }); return; }
        let out = '';
        stream.on('data', d => out += d.toString());
        stream.stderr.on('data', () => {});
        stream.on('close', () => finish({ up: out.trim() === 'active' }));
      });
    });

    conn.on('error', (err) => {
      let msg = err.message || 'Unknown error';
      if (msg.includes('ECONNREFUSED'))    msg = `Connection refused — is SSH running on ${ip}?`;
      else if (msg.includes('ENOTFOUND'))  msg = `Host not found: ${ip}`;
      else if (msg.includes('ECONNRESET')) msg = `Connection reset by ${ip}.`;
      else if (msg.includes('Authentication')) msg = `Authentication failed for ${ip}.`;
      finish({ up: false, error: msg });
    });

    try {
      conn.connect({ host: ip, port: 22, username, password, readyTimeout: 9000 });
    } catch (err) {
      finish({ up: false, error: err.message });
    }
  });
}

app.post('/api/replay/check-services', async (req, res) => {
  const { client, server } = req.body;

  if (!client?.ip || !client?.username || !client?.password || !client?.serviceName || !client?.interfaceName)
    return res.status(400).json({ success: false, error: 'All client fields are required.' });
  if (!server?.ip || !server?.username || !server?.password || !server?.serviceName)
    return res.status(400).json({ success: false, error: 'All server fields are required.' });

  const [clientResult, serverResult] = await Promise.all([
    sshCheckService(client.ip, client.username, client.password, client.serviceName),
    sshCheckService(server.ip, server.username, server.password, server.serviceName),
  ]);

  if (!clientResult.up || !serverResult.up) {
    const parts = [];
    if (!clientResult.up)
      parts.push(clientResult.error
        ? `Client (${client.serviceName}): ${clientResult.error}`
        : `Client service "${client.serviceName}" is not active`);
    if (!serverResult.up)
      parts.push(serverResult.error
        ? `Server (${server.serviceName}): ${serverResult.error}`
        : `Server service "${server.serviceName}" is not active`);
    return res.json({
      success: false,
      error: 'Services are not up, cannot replay traffic. ' + parts.join('; ')
    });
  }

  res.json({ success: true });
});

/* ── Replay: streaming file-by-file replay ── */
const replayJobs = new Map();

app.post('/api/replay/start-init', (req, res) => {
  const { files, client, mode = 'sequential' } = req.body;
  if (!Array.isArray(files) || files.length === 0)
    return res.status(400).json({ success: false, error: 'No files provided.' });
  if (!client?.ip || !client?.username || !client?.password || !client?.interfaceName)
    return res.status(400).json({ success: false, error: 'Client connection details required.' });

  const token = crypto.randomUUID();
  replayJobs.set(token, { files, client, mode, createdAt: Date.now() });
  setTimeout(() => replayJobs.delete(token), 120000);
  res.json({ success: true, token });
});

app.get('/api/replay/start-stream/:token', async (req, res) => {
  const job = replayJobs.get(req.params.token);
  if (!job) { res.status(404).end(); return; }
  replayJobs.delete(req.params.token);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (obj) => { try { res.write(`data: ${JSON.stringify(obj)}\n\n`); } catch (_) {} };
  const { files, client, mode } = job;

  const conn = new Client();
  let clientClosed = false;
  res.on('close', () => { clientClosed = true; try { conn.destroy(); } catch (_) {} });

  const connected = await new Promise((resolve) => {
    const timer = setTimeout(() => { try { conn.destroy(); } catch (_) {} resolve(false); }, 10000);
    conn.on('ready', () => { clearTimeout(timer); resolve(true); });
    conn.on('error', () => { clearTimeout(timer); resolve(false); });
    try {
      conn.connect({ host: client.ip, port: 22, username: client.username, password: client.password, readyTimeout: 9000 });
    } catch (_) { clearTimeout(timer); resolve(false); }
  });

  if (!connected) {
    send({ type: 'error', message: `Could not SSH into client (${client.ip}).` });
    res.end();
    return;
  }

  /* ── helpers ── */

  // Upload a single file via SFTP, returns remote tmp path or null on error
  function uploadFile(i, filePath) {
    const fileName  = path.basename(filePath);
    const localPath = path.join(__dirname, filePath);
    const remoteTmp = `/tmp/dareplay_${Date.now()}_${i}_${fileName}`;

    send({ type: 'file-status', index: i, status: 'uploading' });

    return new Promise((resolve) => {
      conn.sftp((err, sftp) => {
        if (err) {
          send({ type: 'file-status', index: i, status: 'error', error: 'SFTP: ' + err.message });
          return resolve(null);
        }
        const rs = fs.createReadStream(localPath);
        const ws = sftp.createWriteStream(remoteTmp);
        ws.on('close', () => resolve(remoteTmp));
        ws.on('error', (e) => {
          send({ type: 'file-status', index: i, status: 'error', error: 'Upload failed: ' + e.message });
          resolve(null);
        });
        rs.on('error', (e) => {
          send({ type: 'file-status', index: i, status: 'error', error: 'File read error: ' + e.message });
          resolve(null);
        });
        rs.pipe(ws);
      });
    });
  }

  // Run tcpreplay on an already-uploaded remote file
  function replayFile(i, remoteTmp) {
    send({ type: 'file-status', index: i, status: 'replaying' });

    return new Promise((resolve) => {
      const cmd = `tcpreplay -i "${client.interfaceName}" "${remoteTmp}"; RC=$?; rm -f "${remoteTmp}"; exit $RC`;
      conn.exec(cmd, (err, stream) => {
        if (err) {
          send({ type: 'file-status', index: i, status: 'error', error: err.message });
          return resolve();
        }

        let stdOut = '';
        let errOut = '';
        stream.on('data', d => { stdOut += d.toString(); });
        stream.stderr.on('data', d => { errOut += d.toString(); });

        const timeout = setTimeout(() => {
          send({ type: 'file-status', index: i, status: 'error', error: 'Timed out after 5 minutes.' });
          try { stream.close(); } catch (_) {}
          resolve();
        }, 5 * 60 * 1000);

        stream.on('close', (code) => {
          clearTimeout(timeout);
          if (code === 0 || code === 1) {
            send({ type: 'file-status', index: i, status: 'done' });
          } else {
            const msg = (errOut || stdOut).trim() || `Exited with code ${code}`;
            send({ type: 'file-status', index: i, status: 'error', error: msg });
          }
          resolve();
        });
      });
    });
  }

  /* ── sequential mode ── */
  async function runSequential() {
    for (let i = 0; i < files.length; i++) {
      if (clientClosed) break;
      const remoteTmp = await uploadFile(i, files[i]);
      if (!remoteTmp || clientClosed) continue;
      await replayFile(i, remoteTmp);
    }
  }

  /* ── concurrent mode: upload one-by-one, then replay all in parallel ── */
  async function runConcurrent() {
    // Phase 1 — upload all files sequentially (avoids bandwidth spike)
    const remotePaths = [];
    for (let i = 0; i < files.length; i++) {
      if (clientClosed) { remotePaths.push(null); continue; }
      const remoteTmp = await uploadFile(i, files[i]);
      remotePaths.push(remoteTmp);
    }

    if (clientClosed) return;

    // Phase 2 — launch all tcpreplay subprocesses simultaneously
    await Promise.all(
      remotePaths.map((remoteTmp, i) => {
        if (!remoteTmp) return Promise.resolve();
        return replayFile(i, remoteTmp);
      })
    );
  }

  /* ── run ── */
  if (mode === 'concurrent') {
    await runConcurrent();
  } else {
    await runSequential();
  }

  try { conn.destroy(); } catch (_) {}
  if (!clientClosed) { send({ type: 'all-done' }); res.end(); }
});

/* ── Deployment: SSH connect ── */
app.post('/api/deployment/connect', (req, res) => {
  const { ip, username, password, port: sshPort = 22 } = req.body;
  if (!ip || !username || !password)
    return res.status(400).json({ success: false, error: 'IP, username and password are required.' });

  const conn = new Client();
  let settled = false;

  const finish = (result) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);

    if (result.success) {
      const sessionId = crypto.randomUUID();
      sessions.set(sessionId, { conn, ip, username, port: Number(sshPort), createdAt: Date.now() });
      conn.on('error', () => sessions.delete(sessionId));
      conn.on('end',   () => sessions.delete(sessionId));
      res.json({ success: true, sessionId });
    } else {
      try { conn.destroy(); } catch (_) {}
      res.json(result);
    }
  };

  const timer = setTimeout(() =>
    finish({ success: false, error: 'Connection timed out after 10 seconds.' }), 10000);

  conn.on('ready', () => finish({ success: true }));

  conn.on('error', (err) => {
    let msg = err.message || 'Unknown error';
    if (msg.includes('ECONNREFUSED'))    msg = `Connection refused — is SSH running on ${ip}:${sshPort}?`;
    else if (msg.includes('ENOTFOUND'))  msg = `Host not found: ${ip}`;
    else if (msg.includes('ECONNRESET')) msg = 'Connection reset by server.';
    else if (msg.includes('Authentication')) msg = 'Authentication failed — wrong username or password.';
    finish({ success: false, error: msg });
  });

  try {
    conn.connect({ host: ip, port: Number(sshPort), username, password, readyTimeout: 9000 });
  } catch (err) {
    finish({ success: false, error: err.message });
  }
});

/* ── Deployment: list directories (SFTP) ── */
app.post('/api/deployment/dirs', (req, res) => {
  const { sessionId, path: remotePath = '/' } = req.body;
  const sess = getSession(sessionId);
  if (!sess) return res.json({ success: false, error: 'Session expired — please reconnect.' });

  sess.conn.sftp((err, sftp) => {
    if (err) return res.json({ success: false, error: 'SFTP error: ' + err.message });

    sftp.readdir(remotePath, (err, list) => {
      if (err) return res.json({ success: false, error: err.message });

      const S_IFDIR = 0o040000;
      const dirs = list
        .filter(item => (item.attrs.mode & 0o170000) === S_IFDIR)
        .map(item => item.filename)
        .filter(n => n !== '.' && n !== '..')
        .sort((a, b) => a.localeCompare(b));

      res.json({ success: true, dirs });
    });
  });
});

/* ── Deployment: create directory ── */
app.post('/api/deployment/mkdir', (req, res) => {
  const { sessionId, path: remotePath } = req.body;
  const sess = getSession(sessionId);
  if (!sess)     return res.json({ success: false, error: 'Session expired.' });
  if (!remotePath) return res.json({ success: false, error: 'Path required.' });

  sess.conn.exec(`mkdir -p "${remotePath}" && printf __OK__`, (err, stream) => {
    if (err) return res.json({ success: false, error: err.message });
    let out = '', errOut = '';
    stream.on('data', d => out += d);
    stream.stderr.on('data', d => errOut += d);
    stream.on('close', () => {
      out.includes('__OK__')
        ? res.json({ success: true })
        : res.json({ success: false, error: errOut || 'Failed to create directory' });
    });
  });
});

/* ── Deployment: upload TAR + extract ── */
app.post('/api/deployment/upload', upload.single('tarfile'), (req, res) => {
  const { sessionId, remotePath } = req.body;
  const sess      = getSession(sessionId);
  const localFile = req.file?.path;
  const cleanup   = () => { if (localFile) fs.unlink(localFile, () => {}); };

  if (!sess)       { cleanup(); return res.json({ success: false, error: 'Session expired.' }); }
  if (!req.file)   { return res.json({ success: false, error: 'No file received.' }); }
  if (!remotePath) { cleanup(); return res.json({ success: false, error: 'Remote path required.' }); }

  const fileName   = req.file.originalname;
  const remoteFile = remotePath.replace(/\/$/, '') + '/' + fileName;

  sess.conn.sftp((err, sftp) => {
    if (err) { cleanup(); return res.json({ success: false, error: 'SFTP error: ' + err.message }); }

    const readStream  = fs.createReadStream(localFile);
    const writeStream = sftp.createWriteStream(remoteFile);

    writeStream.on('close', () => {
      cleanup();

      // Pick tar flags from extension
      let flags = '-xf';
      if (/\.tar\.gz$|\.tgz$/i.test(fileName))         flags = '-xzf';
      else if (/\.tar\.bz2$|\.tbz2$/i.test(fileName))  flags = '-xjf';
      else if (/\.tar\.xz$/i.test(fileName))            flags = '-xJf';

      // Detect top-level dir from archive, then extract
      const cmd = `cd "${remotePath}" && TOPDIR=$(tar -tf "${fileName}" 2>/dev/null | head -1 | cut -d'/' -f1) && tar ${flags} "${fileName}" && printf "__DONE__:$TOPDIR"`;
      sess.conn.exec(cmd, (err, stream) => {
        if (err) return res.json({ success: false, error: 'tar launch failed: ' + err.message });
        let out = '', errOut = '';
        stream.on('data', d => out += d);
        stream.stderr.on('data', d => errOut += d);
        stream.on('close', (code) => {
          const m = out.match(/__DONE__:(.*)/);
          if (m) {
            const topDir       = m[1].trim();
            const extractedPath = topDir
              ? `${remotePath.replace(/\/$/, '')}/${topDir}`
              : remotePath;
            res.json({ success: true, message: `Extracted to ${remotePath}`, extractedPath });
          } else {
            res.json({ success: false, error: errOut || `tar exited with code ${code}` });
          }
        });
      });
    });

    writeStream.on('error', (err) => {
      cleanup();
      res.json({ success: false, error: 'Upload failed: ' + err.message });
    });

    readStream.pipe(writeStream);
  });
});

/* ── Deployment: remote command execution (SSE streaming) ── */
const execJobs = new Map();

app.post('/api/deployment/exec-init', (req, res) => {
  const { sessionId, command, cwd } = req.body;
  const sess = getSession(sessionId);
  if (!sess) return res.json({ success: false, error: 'Session expired.' });
  if (!command) return res.json({ success: false, error: 'Command required.' });

  const token = crypto.randomUUID();
  execJobs.set(token, { sessionId, command, cwd: cwd || null, createdAt: Date.now() });
  setTimeout(() => execJobs.delete(token), 60000); // auto-expire after 60s if never streamed
  res.json({ success: true, token });
});

app.get('/api/deployment/exec-stream/:token', (req, res) => {
  const job = execJobs.get(req.params.token);
  if (!job) { res.status(404).end(); return; }
  execJobs.delete(req.params.token);

  const sess = getSession(job.sessionId);
  if (!sess) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.write(`data: ${JSON.stringify({ type: 'error', message: 'Session expired.' })}\n\n`);
    res.end();
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (obj) => { try { res.write(`data: ${JSON.stringify(obj)}\n\n`); } catch (_) {} };

  const fullCmd = job.cwd ? `cd "${job.cwd}" && ${job.command}` : job.command;

  sess.conn.exec(fullCmd, (err, stream) => {
    if (err) { send({ type: 'error', message: err.message }); res.end(); return; }

    stream.on('data',        d => send({ type: 'stdout', text: d.toString() }));
    stream.stderr.on('data', d => send({ type: 'stderr', text: d.toString() }));
    stream.on('close', code  => { send({ type: 'done', code }); res.end(); });
  });
});

app.listen(PORT, () => {
  console.log(`DA Automation running at http://localhost:${PORT}`);
});
