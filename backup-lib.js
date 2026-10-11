// Shared helpers for backup.js and restore.js: packing, encryption, Backblaze B2.
// A backup file is:  "HMSBK1" + salt(16) + iv(12) + AES-256-GCM(gzip(JSON)) + authTag(16)
// The key comes from BACKUP_PASSPHRASE. Without that passphrase a backup file is unreadable.
const crypto = require('crypto');
const zlib = require('zlib');
const { EJSON } = require('mongoose').mongo.BSON;

const MAGIC = Buffer.from('HMSBK1');

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, 32);
}

function pack(data) {
  // EJSON "canonical" keeps dates / numbers / ids exactly as they were.
  const json = EJSON.stringify(data, { relaxed: false });
  return zlib.gzipSync(Buffer.from(json, 'utf8'));
}
function unpack(buf) {
  return EJSON.parse(zlib.gunzipSync(buf).toString('utf8'), { relaxed: false });
}

function encrypt(plain, passphrase) {
  if (!passphrase || passphrase.length < 12) throw new Error('BACKUP_PASSPHRASE must be set and at least 12 characters long');
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', deriveKey(passphrase, salt), iv);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, salt, iv, body, c.getAuthTag()]);
}
function decrypt(file, passphrase) {
  if (!file.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Not a backup file made by this system');
  const salt = file.subarray(6, 22), iv = file.subarray(22, 34);
  const tag = file.subarray(file.length - 16), body = file.subarray(34, file.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', deriveKey(passphrase, salt), iv);
  d.setAuthTag(tag);
  try { return Buffer.concat([d.update(body), d.final()]); }
  catch { throw new Error('Wrong passphrase, or the backup file is damaged'); }
}

// ── Backblaze B2 (S3-compatible API) ─────────────────────────────────────────
function b2Configured(env = process.env) {
  return Boolean(env.B2_ENDPOINT && env.B2_KEY_ID && env.B2_APP_KEY && env.B2_BUCKET);
}
function b2Client(env = process.env) {
  const { S3Client } = require('@aws-sdk/client-s3');
  const region = (env.B2_ENDPOINT.match(/s3\.([^.]+)\.backblazeb2\.com/) || [])[1] || 'us-west-004';
  return new S3Client({
    endpoint: env.B2_ENDPOINT, region, forcePathStyle: true,
    credentials: { accessKeyId: env.B2_KEY_ID, secretAccessKey: env.B2_APP_KEY },
  });
}
const PREFIX = 'hms-backups/';

async function b2Upload(key, buf, env = process.env) {
  const { PutObjectCommand } = require('@aws-sdk/client-s3');
  await b2Client(env).send(new PutObjectCommand({ Bucket: env.B2_BUCKET, Key: PREFIX + key, Body: buf }));
}
async function b2List(env = process.env) {
  const { ListObjectsV2Command } = require('@aws-sdk/client-s3');
  const c = b2Client(env); const out = []; let token;
  do {
    const r = await c.send(new ListObjectsV2Command({ Bucket: env.B2_BUCKET, Prefix: PREFIX, ContinuationToken: token }));
    (r.Contents || []).forEach(o => out.push({ key: o.Key, size: o.Size, modified: o.LastModified }));
    token = r.IsTruncated ? r.NextContinuationToken : undefined;
  } while (token);
  return out.sort((a, b) => a.modified - b.modified);
}
async function b2Download(key, env = process.env) {
  const { GetObjectCommand } = require('@aws-sdk/client-s3');
  const r = await b2Client(env).send(new GetObjectCommand({ Bucket: env.B2_BUCKET, Key: key }));
  return Buffer.from(await r.Body.transformToByteArray());
}
async function b2Delete(key, env = process.env) {
  const { DeleteObjectCommand } = require('@aws-sdk/client-s3');
  await b2Client(env).send(new DeleteObjectCommand({ Bucket: env.B2_BUCKET, Key: key }));
}

module.exports = { pack, unpack, encrypt, decrypt, b2Configured, b2Upload, b2List, b2Download, b2Delete, PREFIX };
