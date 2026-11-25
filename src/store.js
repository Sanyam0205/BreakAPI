import { readFileSync, writeSync, openSync, closeSync, fsyncSync, renameSync, mkdirSync, existsSync, copyFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

/** The data file exists but cannot be used. Nothing was changed; the message says what to do. */
export class StoreError extends Error {}

const BACKUP_EVERY_MS = 5 * 60_000;

/**
 * Small JSON-file store. Writes are atomic (tmp + fsync + rename) and owner-only. A corrupt file
 * fails closed: it is never overwritten or auto-recovered. `db.json.bak` is a byte copy of the last
 * good file (taken at start and at most every few minutes), with the same owner-only mode, so
 * encrypted fields stay encrypted and nothing is ever written in plaintext.
 */
export class Store {
  constructor(dir, { backupEveryMs = BACKUP_EVERY_MS } = {}) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = join(dir, 'db.json');
    this.backupFile = `${this.file}.bak`;
    this.backupEveryMs = backupEveryMs;
    this.lastBackup = 0;
    this.timer = null;
    if (existsSync(this.file)) {
      this.data = this.#load();
      this.#backup();
    } else {
      this.data = { projects: {}, scans: {} };
    }
  }

  #load() {
    try {
      const data = JSON.parse(readFileSync(this.file, 'utf8'));
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('it does not hold a JSON object');
      return data;
    } catch (err) {
      const hint = existsSync(this.backupFile)
        ? `A backup from an earlier good state is at ${this.backupFile}; check that it is intact, then copy it over ${this.file}.`
        : 'No backup file exists; restore the file from your own backups.';
      throw new StoreError(`breakAPI cannot start: the data file ${this.file} is unreadable (${err.message}). It has not been changed or deleted. ${hint}`);
    }
  }

  #backup() {
    try {
      copyFileSync(this.file, this.backupFile);
      chmodSync(this.backupFile, 0o600);
      this.lastBackup = Date.now();
    } catch (err) {
      // Saving must not fail because the backup did, but the operator should know.
      console.error(`breakAPI: could not refresh ${this.backupFile}: ${err.message}`);
    }
  }

  /** Coalesce frequent writes (scans update often). */
  save() {
    if (this.timer) return;
    this.timer = setTimeout(() => this.saveNow(), 250);
  }

  saveNow() {
    clearTimeout(this.timer);
    this.timer = null;
    const tmp = `${this.file}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, JSON.stringify(this.data));
      fsyncSync(fd); // shortcut: the directory entry is not fsynced; a crash right after rename can still lose the newest save
    } finally {
      closeSync(fd);
    }
    // The file being replaced is the last complete one, so it is the right thing to keep.
    if (existsSync(this.file) && Date.now() - this.lastBackup >= this.backupEveryMs) this.#backup();
    renameSync(tmp, this.file);
  }
}
