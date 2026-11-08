'use strict';
// Nathaya Tunnel: private local archives, SSH-forwarded admin UI; no npm dependencies.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { pipeline } = require('stream');
const run = promisify(execFile);
const pipe = promisify(pipeline);
const MAX_UPLOAD = 512 * 1024 * 1024;
const PORT = 5000;
const directory = process.argv[2];
const secret = process.env.NATHAYA_BACKUP_SECRET;
delete process.env.NATHAYA_BACKUP_SECRET;

function checkDirectory(value) {
    if (typeof value !== 'string' || !value.startsWith('/root/') || path.resolve(value) !== value) {
        throw new Error('Supply a private absolute directory below /root.');
    }
    const parts = value.split('/').slice(1);
    let current = '';
    for (const part of parts) {
        current += '/' + part;
        const stat = fs.lstatSync(current);
        if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o077)) {
            throw new Error('Every archive directory must be root-owned and mode 0700.');
        }
    }
}

try {
    if (!process.getuid || process.getuid() !== 0) throw new Error('Administrator privileges required.');
    if (typeof secret !== 'string' || secret.length < 32 || /[\r\n]/.test(secret)) {
        throw new Error('Supply a 32+ character runtime admin secret; it is never printed.');
    }
    checkDirectory(directory);
} catch (error) {
    console.error(error.message);
    process.exit(1);
}
process.umask(0o077);
const digest = value => crypto.createHash('sha256').update(value).digest();
const expectedAuth = digest('Basic ' + Buffer.from('admin:' + secret).toString('base64'));
const childOptions = {
    shell: false,
    timeout: 10 * 60 * 1000,
    maxBuffer: 64 * 1024,
    env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', HOME: '/root', LANG: 'C.UTF-8' }
};
let busy = false;

function reply(res, status, message) {
    res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(message);
}

async function backend(args) {
    // Fixed executable/script, argument array, no shell interpolation or request-controlled commands.
    await run('/bin/bash', ['/usr/bin/backuprestore', ...args], childOptions);
}

async function readText(req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
        size += chunk.length;
        if (size > 8192) throw new Error('Request too large.');
        chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString('utf8');
}

function archivePath(name) {
    if (typeof name !== 'string' || !/^nathaya-(?:backup|upload)-[a-f0-9]{32}\.tar\.gz$/.test(name)) {
        throw new Error('Select an archive created or uploaded in this session directory.');
    }
    return path.join(directory, name);
}

function page(nonce) {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Nathaya Backup / Restore</title>
<style nonce="${nonce}">body{background:#101923;color:#eef6ff;font:16px system-ui;margin:2rem auto;max-width:42rem;padding:1rem}h1{color:#28d6e7}button{background:#f39631;padding:.7rem;border:0;cursor:pointer}input{margin:.7rem 0;max-width:100%}section{border:1px solid #28d6e7;padding:1rem;margin:1rem 0}code{overflow-wrap:anywhere}#status{white-space:pre-wrap}</style></head>
<body><h1>NATHAYA TUNNEL</h1><h2>Private backup / restore</h2>
<p>Root-only archives stay on this server. Use an SSH local port forward. No Telegram delivery or public download URLs.</p>
<section><h3>Backup</h3><button id="backup">Create and download a local backup</button></section>
<section><h3>Restore</h3><p>Upload a tar.gz archive (maximum 512 MiB). Files are validated before privileged writes. Original local uploads are retained.</p>
<input id="file" type="file" accept=".tar.gz,.tgz"><button id="upload">Upload only</button>
<p>Uploaded archive: <code id="archive">none</code></p>
<p>Archives include SSH/account databases, native Xray protocols, OpenVPN/CA, Let's Encrypt, TLS keys and Nathaya notification credentials. Keep them private. Restore overwrites this privileged state with root-only data permissions. Take a backup first. Type <strong>RESTORE</strong> below to confirm.</p>
<input id="confirmation" autocomplete="off" placeholder="RESTORE"><button id="restore">Validate and restore</button>
<p>No service is started or restarted automatically. Review service access and TLS configuration manually. In-tree OpenVPN/Let's Encrypt file links are snapshotted as regular files; existing destination links are refused. Multi-file restore is not transactional.</p></section>
<p id="status" role="status"></p>
<script nonce="${nonce}">
'use strict';
let archive = '';
const status = document.getElementById('status');
async function post(route, body, type) {
    const response = await fetch(route, {method:'POST', headers:{'Content-Type':type,'X-Nathaya-Action':'1'},body});
    if (!response.ok) throw new Error(await response.text());
    return response;
}
async function action(work) {
    document.querySelectorAll('button').forEach(button => button.disabled = true);
    status.textContent = 'Working...';
    try { await work(); } catch (error) { status.textContent = error.message; }
    finally { document.querySelectorAll('button').forEach(button => button.disabled = false); }
}
document.getElementById('backup').onclick = () => action(async () => {
    const response = await post('/backup', '', 'text/plain');
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = 'nathaya-backup.tar.gz'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    status.textContent = 'Download prepared. The private server archive is retained.';
});
document.getElementById('upload').onclick = () => action(async () => {
    const file = document.getElementById('file').files[0];
    if (!file || file.size > 536870912) throw new Error('Choose an archive of at most 512 MiB.');
    archive = await (await post('/upload', file, 'application/gzip')).text();
    document.getElementById('archive').textContent = archive;
    status.textContent = 'Upload retained privately. No restore has been performed.';
});
document.getElementById('restore').onclick = () => action(async () => {
    if (!archive) throw new Error('Upload an archive first.');
    const confirmation = document.getElementById('confirmation').value;
    if (confirmation !== 'RESTORE') throw new Error('Type RESTORE to confirm privileged overwrite.');
    const body = new URLSearchParams({archive,confirmation});
    status.textContent = await (await post('/restore', body, 'application/x-www-form-urlencoded')).text();
});
</script></body></html>`;
}

const server = http.createServer(async (req, res) => {
    const nonce = crypto.randomBytes(18).toString('base64');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    const host = req.headers.host;
    if (host !== '127.0.0.1:5000' && host !== 'localhost:5000') return reply(res, 403, 'Use the SSH-forwarded loopback URL on port 5000.');
    if (!crypto.timingSafeEqual(expectedAuth, digest(req.headers.authorization || ''))) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Nathaya admin", charset="UTF-8"');
        return reply(res, 401, 'Administrator authentication required.');
    }
    if (req.method === 'GET' && req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page(nonce));
    }
    if (req.method !== 'POST' || !['/backup', '/upload', '/restore'].includes(req.url)) return reply(res, 404, 'Not found.');
    if (req.headers['x-nathaya-action'] !== '1' || (req.headers.origin && req.headers.origin !== 'http://' + host)) {
        return reply(res, 403, 'Same-origin admin action required.');
    }
    if (busy) return reply(res, 409, 'Another backup/restore operation is running.');
    busy = true;
    try {
        checkDirectory(directory);
        if (req.url === '/backup') {
            const name = 'nathaya-backup-' + crypto.randomBytes(16).toString('hex') + '.tar.gz';
            const destination = archivePath(name);
            await backend(['backup', destination]);
            const stat = fs.lstatSync(destination);
            if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || stat.nlink !== 1 || (stat.mode & 0o077)) throw new Error('Unsafe archive.');
            res.writeHead(200, { 'Content-Type': 'application/gzip', 'Content-Length': stat.size, 'Content-Disposition': 'attachment; filename="nathaya-backup.tar.gz"' });
            await pipe(fs.createReadStream(destination, { flags: fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW }), res);
        } else if (req.url === '/upload') {
            if (req.headers['content-type'] !== 'application/gzip' || Number(req.headers['content-length'] || 0) > MAX_UPLOAD) {
                return reply(res, 400, 'Expected an archive of at most 512 MiB.');
            }
            const name = 'nathaya-upload-' + crypto.randomBytes(16).toString('hex') + '.tar.gz';
            const destination = archivePath(name);
            let size = 0;
            const output = fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 });
            req.on('data', chunk => {
                size += chunk.length;
                if (size > MAX_UPLOAD) req.destroy(new Error('Upload limit exceeded.'));
            });
            try {
                await pipe(req, output);
                if (!size) throw new Error('Empty upload.');
            } catch (error) {
                try { fs.unlinkSync(destination); } catch (_) { /* Failed uploads only. */ }
                throw error;
            }
            reply(res, 200, name);
        } else {
            const form = new URLSearchParams(await readText(req));
            if (form.get('confirmation') !== 'RESTORE') return reply(res, 400, 'Type RESTORE to confirm privileged overwrite.');
            await backend(['restore', archivePath(form.get('archive')), '--confirm-privileged-overwrite']);
            reply(res, 200, 'Restore files written; original archive retained. Private data is root-only. No services started or restarted; review service access and TLS configuration manually.');
        }
    } catch (error) {
        // Never reflect child stderr, archive data, credentials or arbitrary filenames.
        if (!res.headersSent && !res.destroyed) reply(res, 400, 'Operation failed. Check the private path, archive policy, permissions, free space and backend availability.');
        else res.destroy();
        console.error('Backup/restore operation failed; no private details logged.');
    } finally {
        busy = false;
    }
});
server.requestTimeout = 10 * 60 * 1000;
server.headersTimeout = 30000;
server.maxHeadersCount = 50;
server.on('error', () => { console.error('Private backup UI could not listen.'); process.exitCode = 1; });
server.listen(PORT, '127.0.0.1', () => {
    console.log('Nathaya backup UI: http://127.0.0.1:5000 (SSH forward; admin authentication required).');
});
