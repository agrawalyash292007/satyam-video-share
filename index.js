const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const os = require('os');
const path = require('path');

const app = express();
const appVersion = '2026-09-26.3';
const port = Number(process.env.PORT) || 3000;
const ownerKey = process.env.OWNER_KEY;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseBucket = process.env.SUPABASE_BUCKET || 'videos';
const useSupabase = Boolean(supabaseUrl && supabaseKey);
const localUploadsDirectory = path.join(__dirname, 'uploads');
const temporaryUploadDirectory = path.join(os.tmpdir(), 'satyam-video-uploads');
const publicDirectory = path.join(__dirname, 'public');
const maxVideoSize = 100 * 1024 * 1024;
const allowedVideoExtensions = new Set(['.mp4', '.webm', '.ogg', '.mov', '.m4v', '.mkv']);
const allowedVideoTypes = new Set([
  'video/mp4',
  'video/webm',
  'video/ogg',
  'video/quicktime',
  'video/x-m4v',
  'video/x-matroska'
]);

if (!ownerKey || ownerKey.length < 16) {
  console.error('Set OWNER_KEY to a private key of at least 16 characters.');
  process.exit(1);
}

if (Boolean(supabaseUrl) !== Boolean(supabaseKey)) {
  console.error('Set both SUPABASE_URL and SUPABASE_SECRET_KEY (or SUPABASE_SERVICE_ROLE_KEY), or leave both unset for local storage.');
  process.exit(1);
}

if (process.env.NODE_ENV === 'production' && !useSupabase) {
  console.error('Production requires SUPABASE_URL and SUPABASE_SECRET_KEY (or SUPABASE_SERVICE_ROLE_KEY).');
  process.exit(1);
}

const newFormatKeyPrefixes = ['sb_secret_', 'sb_publishable_'];

function isNewFormatKey(key) {
  return newFormatKeyPrefixes.some((prefix) => key.startsWith(prefix));
}

// Reports the shape of the configured key without ever revealing any of its characters,
// so a mis-pasted credential can be diagnosed from the outside.
function describeKey(key) {
  if (!key) {
    return { format: 'missing', length: 0 };
  }

  let format = 'unrecognized';
  if (key.startsWith('sb_secret_')) format = 'sb_secret';
  else if (key.startsWith('sb_publishable_')) format = 'sb_publishable';
  else if (key.startsWith('sb_temp_')) format = 'sb_temp';
  else if (key.startsWith('eyJ')) format = 'legacy-jwt';

  return {
    format,
    length: key.length,
    hasSurroundingWhitespace: key !== key.trim(),
    hasQuoteCharacters: /^["'].*["']$/.test(key) || key.includes('"') || key.includes("'"),
    hasWhitespace: /\s/.test(key)
  };
}

// New-format Supabase keys (`sb_secret_…`, `sb_publishable_…`) are opaque secrets, not
// JWTs, so they must only ever travel in the `apikey` header. Sending one as
// `Authorization: Bearer …` makes the API gateway reject the request with
// "Invalid Compact JWS". Legacy keys are JWTs and are accepted in both headers.
function supabaseHeaders(extra) {
  const headers = { apikey: supabaseKey, ...extra };

  if (!isNewFormatKey(supabaseKey)) {
    headers.Authorization = `Bearer ${supabaseKey}`;
  }

  return headers;
}

async function supabaseRequest(method, endpoint, options = {}) {
  const response = await fetch(`${supabaseOrigin}${endpoint}`, {
    method,
    headers: supabaseHeaders(options.headers),
    body: options.body
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    const error = new Error(detail || `${response.status} ${response.statusText}`);
    error.status = response.status;
    throw error;
  }

  if (options.raw) {
    return response.text();
  }

  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

const supabaseOrigin = supabaseUrl ? supabaseUrl.replace(/\/+$/, '') : null;

function publicVideoUrl(name) {
  return `${supabaseOrigin}/storage/v1/object/public/${supabaseBucket}/${encodeURIComponent(name)}`;
}

fs.mkdirSync(localUploadsDirectory, { recursive: true });
fs.mkdirSync(temporaryUploadDirectory, { recursive: true });

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
app.use(express.static(publicDirectory));

function ownerOnly(req, res, next) {
  const suppliedKey = req.get('x-owner-key') || '';
  const expectedKey = Buffer.from(ownerKey);
  const suppliedKeyBuffer = Buffer.from(suppliedKey);

  if (
    suppliedKeyBuffer.length !== expectedKey.length ||
    !crypto.timingSafeEqual(suppliedKeyBuffer, expectedKey)
  ) {
    return res.status(403).json({ error: 'Owner key required.' });
  }

  next();
}

function isVideoFilename(filename) {
  return allowedVideoExtensions.has(path.extname(filename).toLowerCase());
}

function createObjectName(file) {
  const extension = path.extname(file.originalname).toLowerCase();
  return `${Date.now()}-${crypto.randomUUID()}${extension}`;
}

const upload = multer({
  storage: multer.diskStorage({
    destination: temporaryUploadDirectory,
    filename: (req, file, cb) => {
      cb(null, createObjectName(file));
    }
  }),
  limits: {
    fileSize: maxVideoSize,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    const type = file.mimetype.toLowerCase();

    if (!allowedVideoExtensions.has(extension) || !allowedVideoTypes.has(type)) {
      return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'video'));
    }

    cb(null, true);
  }
}).single('video');

async function listVideos() {
  if (useSupabase) {
    const files = await supabaseRequest(
      'POST',
      `/storage/v1/object/list/${encodeURIComponent(supabaseBucket)}`,
      {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefix: '', limit: 1000 })
      }
    );

    return (Array.isArray(files) ? files : [])
      .filter((file) => file && file.name && isVideoFilename(file.name))
      .sort((first, second) => second.name.localeCompare(first.name, undefined, { numeric: true }))
      .map((file) => ({ name: file.name, url: publicVideoUrl(file.name) }));
  }

  const entries = await fs.promises.readdir(localUploadsDirectory, { withFileTypes: true });

  return entries
    .filter((entry) => entry.isFile() && isVideoFilename(entry.name))
    .map((entry) => entry.name)
    .sort((first, second) => second.localeCompare(first, undefined, { numeric: true }))
    .map((name) => ({ name, url: `/uploads/${encodeURIComponent(name)}` }));
}

async function saveVideo(file) {
  if (useSupabase) {
    await supabaseRequest(
      'POST',
      `/storage/v1/object/${encodeURIComponent(supabaseBucket)}/${encodeURI(file.filename)}`,
      {
        headers: { 'Content-Type': file.mimetype, 'x-upsert': 'false' },
        body: await fs.promises.readFile(file.path)
      }
    );

    return { name: file.filename, url: publicVideoUrl(file.filename) };
  }

  const destination = path.join(localUploadsDirectory, file.filename);
  await fs.promises.copyFile(file.path, destination);
  return { name: file.filename, url: `/uploads/${encodeURIComponent(file.filename)}` };
}

async function removeVideo(filename) {
  if (useSupabase) {
    await supabaseRequest(
      'DELETE',
      `/storage/v1/object/${encodeURIComponent(supabaseBucket)}/${encodeURI(filename)}`
    );
    return;
  }

  await fs.promises.unlink(path.join(localUploadsDirectory, filename));
}

app.get('/owner/verify', ownerOnly, (req, res) => {
  res.json({ success: true, version: appVersion });
});

app.get('/owner/storage-status', ownerOnly, async (req, res) => {
  if (!useSupabase) {
    return res.json({ version: appVersion, mode: 'local', ok: true });
  }

  const config = {
    version: appVersion,
    mode: 'supabase',
    url: supabaseUrl,
    bucket: supabaseBucket,
    key: describeKey(supabaseKey)
  };

  try {
    await supabaseRequest(
      'POST',
      `/storage/v1/object/list/${encodeURIComponent(supabaseBucket)}`,
      {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefix: '', limit: 1 })
      }
    );
  } catch (error) {
    return res.status(500).json({ ...config, ok: false, error: error.message });
  }

  res.json({ ...config, ok: true });
});

app.post('/upload', ownerOnly, upload, async (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Choose a video to upload.' });
  }

  try {
    const video = await saveVideo(req.file);
    res.status(201).json({ success: true, ...video });
  } catch (error) {
    next(error);
  } finally {
    await fs.promises.unlink(req.file.path).catch(() => {});
  }
});

app.get('/videos', async (req, res, next) => {
  try {
    res.json(await listVideos());
  } catch (error) {
    next(error);
  }
});

app.delete('/videos/:filename', ownerOnly, async (req, res, next) => {
  const filename = req.params.filename;

  if (path.basename(filename) !== filename || !isVideoFilename(filename)) {
    return res.status(400).json({ error: 'Invalid video name.' });
  }

  try {
    await removeVideo(filename);
    res.json({ success: true });
  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Video not found.' });
    }

    next(error);
  }
});

if (!useSupabase) {
  app.use('/uploads', express.static(localUploadsDirectory, {
    dotfiles: 'deny',
    fallthrough: false,
    index: false,
    maxAge: '1h'
  }));
}

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    const isTooLarge = error.code === 'LIMIT_FILE_SIZE';
    return res.status(isTooLarge ? 413 : 400).json({
      error: isTooLarge ? 'Video must be 100 MB or smaller.' : 'Upload a supported video file.'
    });
  }

  if (error && error.status === 404) {
    return res.status(404).json({ error: 'Video not found.' });
  }

  console.error(error);
  res.status(500).json({ error: 'Something went wrong.' });
});

app.listen(port, () => {
  console.log(`Video site running at http://localhost:${port}`);
});