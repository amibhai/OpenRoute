// A small persistent ring buffer of what the ladder decided and why, for the
// UI's timeline and for bug reports. Writes are best-effort: logging never
// fails the operation that's being logged.

const MAX_EVENTS = 300;

export function createEventLog(store, { max = MAX_EVENTS, now = () => Date.now() } = {}) {
  return {
    add(type, data = {}) {
      return store.tx(["eventLog"], (d) => {
        const list = Array.isArray(d.eventLog) ? d.eventLog : [];
        list.push({ ...data, at: now(), event: type }); // `event` can't be clobbered by data.type
        if (list.length > max) list.splice(0, list.length - max);
        d.eventLog = list;
      }).catch(() => {});
    },
    async list(limit = max) {
      const list = await store.get("eventLog", []);
      return list.slice(-limit);
    },
    clear() {
      return store.tx(["eventLog"], (d) => { d.eventLog = undefined; });
    }
  };
}
