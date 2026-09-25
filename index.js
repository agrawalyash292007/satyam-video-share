const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const os = require('os');
const path = require('path');

const app = express();
const appVersion = '2026-09-26.4';
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

function isJwtShaped(key) {
  if (typeof key !== 'string' || !key) {
    return false;
  }

  const parts = key.split('.');
  return parts.length === 3 && parts.every((part) => /^[A-Za-z0-9_-]+$/.test(part));
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
  else if (isJwtShaped(key)) format = 'legacy-jwt';

  return {
    format,
    length: key.length,
    hasSurroundingWhitespace: key !== key.trim(),
    hasQuoteCharacters: key.includes('"') || key.includes("'"),
    hasWhitespace: /\s/.test(key)
  };
}

const supabaseOrigin = supabaseUrl ? supabaseUrl.replace(/\/+$/, '') : null;

// A key can authenticate in two different ways. Legacy `service_role` keys are JWTs, so
// they are accepted as `Authorization: Bearer …`. New opaque keys (`sb_secret_…`) are
// rejected as a bearer token with "Invalid Compact JWS" and must travel in `apikey` only.
// Rather than guess from the string shape, try the likely style first and fall back to the
// other one on a 401/403, then remember whichever style worked for later requests.
let preferredAuthStyle = isJwtShaped(supabaseKey) ? 'bearer' : 'apikey-only';
let resolvedAuthStyle = null;

function buildSupabaseInit(method, endpoint, options, style) {
  const headers = { apikey: supabaseKey, ...options.headers };

  if (style === 'bearer') {
    headers.Authorization = `Bearer ${supabaseKey}`;
  }

  return {
    method,
    headers,
    body: options.body,
    cache: 'no-store'
  };
}

async function supabaseRequest(method, endpoint, options = {}) {
  const url = `${supabaseOrigin}${endpoint}`;
  const styles = resolvedAuthStyle
    ? [resolvedAuthStyle]
    : [preferredAuthStyle, preferredAuthStyle === 'bearer' ? 'apikey-only' : 'bearer'];

  let lastError;

  for (const style of styles) {
    const response = await fetch(url, buildSupabaseInit(method, endpoint, options, style));
    const text = response.ok ? await response.text() : await response.text().catch(() => '');

    if (response.ok) {
      resolvedAuthStyle = style;
      if (resolvedAuthStyle !== preferredAuthStyle) {
        console.log(`Supabase auth style resolved to "${style}" for this key format.`);
      }
      return options.raw || !text ? text : JSON.parse(text);
    }

    const error = new Error(text || `${response.status} ${response.statusText}`);
    error.status = response.status;
    lastError = error;

    if (response.status !== 401 && response.status !== 403) {
      break;
    }
  }

  throw lastError;
}

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

  res.json({ ...config, authStyle: resolvedAuthStyle, ok: true });
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