import time

try:
    import cPickle as pickle
except ImportError:
    import pickle


class SimpleCache:
    """A SimpleCache for testing. Copied from Werkzeug."""

    def __init__(self, threshold=500, default_timeout=300):
        self.default_timeout = default_timeout
        self._cache = {}
        self.clear = self._cache.clear
        self._threshold = threshold

    def _prune(self):
        if len(self._cache) > self._threshold:
            now = time.time()
            toremove = []
            for idx, (key, (expires, _)) in enumerate(self._cache.items()):
                if (expires != 0 and expires <= now) or idx % 3 == 0:
                    toremove.append(key)
            for key in toremove:
                self._cache.pop(key, None)

    def _normalize_timeout(self, timeout):
        if timeout is None:
            timeout = self.default_timeout
        if timeout > 0:
            timeout = time.time() + timeout
        return timeout

    def get(self, key):
        try:
            expires, value = self._cache[key]
            if expires == 0 or expires > time.time():
                return pickle.loads(value)
        except (KeyError, pickle.PickleError):
            return None

    def set(self, key, value, timeout=None):
        expires = self._normalize_timeout(timeout)
        self._prune()
        self._cache[key] = (expires, pickle.dumps(value, pickle.HIGHEST_PROTOCOL))
        return True

    def delete(self, key):
        return self._cache.pop(key, None) is not None

    def has(self, key):
        try:
            expires, value = self._cache[key]
            return expires == 0 or expires > time.time()
        except KeyError:
            return False
