// Modern syntax: private fields, a static block, optional chaining, logical assignment
// and Array.prototype.at. The point of this fixture is that the path setter inside is
// still found, not merely that the file parses.
export class Settings {
  #store = {};

  static defaults = { retries: 1 };

  static {
    Settings.initialised = true;
  }

  set(path, value) {
    const parts = path?.split('.') ?? [];
    let cursor = this.#store;
    for (const part of parts.slice(0, -1)) {
      cursor = cursor[part] ??= {};
    }
    cursor[parts.at(-1)] = value;
    return this;
  }

  get(path) {
    return path.split('.').reduce((node, part) => node?.[part], this.#store);
  }
}

export const probe = async (source) => {
  const body = await source.readPayload?.();
  return body ?? {};
};
