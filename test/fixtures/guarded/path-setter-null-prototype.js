// Guarded: prototype-less all the way down. Compare
// vulnerable/path-setter-null-root.js, which differs only in creating its
// intermediates as {}.
export class Registry {
  #entries = Object.create(null);

  define(path, value) {
    const parts = path.split('/');
    let cursor = this.#entries;
    for (const part of parts.slice(0, -1)) {
      if (cursor[part] === undefined) {
        cursor[part] = Object.create(null);
      }
      cursor = cursor[part];
    }
    cursor[parts[parts.length - 1]] = value;
    return this;
  }
}
