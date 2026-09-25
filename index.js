const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const path = require('path');

const app = express();
const port = Number(process.env.PORT) || 3000;
const ownerKey = process.env.OWNER_KEY;
const uploadsDirectory = path.join(__dirname, 'uploads');
const publicDirectory = path.join(__dirname, 'public');
const maxVideoSize = 500 * 1024 * 1024;
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

fs.mkdirSync(uploadsDirectory, { recursive: true });

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

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDirectory,
    filename: (req, file, cb) => {
      const extension = path.extname(file.originalname).toLowerCase();
      cb(null, `${Date.now()}-${crypto.randomUUID()}${extension}`);
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

app.get('/owner/verify', ownerOnly, (req, res) => {
  res.json({ success: true });
});

app.post('/upload', ownerOnly, upload, (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Choose a video to upload.' });
  }

  res.status(201).json({
    success: true,
    videoUrl: `/uploads/${encodeURIComponent(req.file.filename)}`
  });
});

app.get('/videos', (req, res, next) => {
  fs.readdir(uploadsDirectory, { withFileTypes: true }, (error, entries) => {
    if (error) {
      return next(error);
    }

    const videos = entries
      .filter((entry) => {
        return entry.isFile() && allowedVideoExtensions.has(path.extname(entry.name).toLowerCase());
      })
      .map((entry) => entry.name)
      .sort((first, second) => second.localeCompare(first, undefined, { numeric: true }))
      .map((filename) => `/uploads/${encodeURIComponent(filename)}`);

    res.json(videos);
  });
});

app.delete('/uploads/:filename', ownerOnly, (req, res, next) => {
  const filename = req.params.filename;
  const extension = path.extname(filename).toLowerCase();

  if (path.basename(filename) !== filename || !allowedVideoExtensions.has(extension)) {
    return res.status(400).json({ error: 'Invalid video name.' });
  }

  fs.unlink(path.join(uploadsDirectory, filename), (error) => {
    if (!error) {
      return res.json({ success: true });
    }

    if (error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Video not found.' });
    }

    next(error);
  });
});

app.use('/uploads', express.static(uploadsDirectory, {
  dotfiles: 'deny',
  fallthrough: false,
  index: false,
  maxAge: '1h'
}));

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    const isTooLarge = error.code === 'LIMIT_FILE_SIZE';
    return res.status(isTooLarge ? 413 : 400).json({
      error: isTooLarge ? 'Video must be 500 MB or smaller.' : 'Upload a supported video file.'
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