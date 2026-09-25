const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const os = require('os');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = Number(process.env.PORT) || 3000;
const ownerKey = process.env.OWNER_KEY;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseBucket = process.env.SUPABASE_BUCKET || 'videos';
const useSupabase = Boolean(supabaseUrl && supabaseServiceRoleKey);
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

if (Boolean(supabaseUrl) !== Boolean(supabaseServiceRoleKey)) {
  console.error('Set both SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY, or leave both unset for local storage.');
  process.exit(1);
}

if (process.env.NODE_ENV === 'production' && !useSupabase) {
  console.error('Production requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
  process.exit(1);
}

fs.mkdirSync(localUploadsDirectory, { recursive: true });
fs.mkdirSync(temporaryUploadDirectory, { recursive: true });

const supabase = useSupabase
  ? createClient(supabaseUrl, supabaseServiceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  })
  : null;

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
    const { data, error } = await supabase.storage.from(supabaseBucket).list('', { limit: 1000 });

    if (error) {
      throw new Error(error.message);
    }

    return (data || [])
      .filter((file) => file && isVideoFilename(file.name))
      .sort((first, second) => second.name.localeCompare(first.name, undefined, { numeric: true }))
      .map((file) => {
        const { data: publicData } = supabase.storage.from(supabaseBucket).getPublicUrl(file.name);
        return { name: file.name, url: publicData.publicUrl };
      });
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
    const { error } = await supabase.storage.from(supabaseBucket).upload(file.filename, fs.createReadStream(file.path), {
      contentType: file.mimetype,
      upsert: false
    });

    if (error) {
      throw new Error(error.message);
    }

    const { data: publicData } = supabase.storage.from(supabaseBucket).getPublicUrl(file.filename);
    return { name: file.filename, url: publicData.publicUrl };
  }

  const destination = path.join(localUploadsDirectory, file.filename);
  await fs.promises.copyFile(file.path, destination);
  return { name: file.filename, url: `/uploads/${encodeURIComponent(file.filename)}` };
}

async function removeVideo(filename) {
  if (useSupabase) {
    const { error } = await supabase.storage.from(supabaseBucket).remove([filename]);

    if (error) {
      throw new Error(error.message);
    }

    return;
  }

  await fs.promises.unlink(path.join(localUploadsDirectory, filename));
}

app.get('/owner/verify', ownerOnly, (req, res) => {
  res.json({ success: true });
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