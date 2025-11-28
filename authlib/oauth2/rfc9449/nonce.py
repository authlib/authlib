import time
from threading import Lock
from typing import Protocol

from authlib.common.cache import LRUCache
from authlib.common.security import generate_token


class DPoPNonceCache(Protocol):
    def __getitem__(self, origin: str) -> str:
        """
        Get the nonce saved for a specific origin url
        :param origin: the url of the nonce to get
        :return: the nonce
        """
        ...

    def __setitem__(self, origin: str, nonce: str) -> None:
        """
        Set a nonce for the specific origin url
        :param origin: the url of the nonce to set
        :param nonce: the nonce to set
        """
        ...


class DPoPNonceGenerator(Protocol):
    def next(self) -> str:
        """
        Compute and return the next nonce for this server
        :return: the nonce
        """
        ...

    def check(self, nonce: str) -> bool:
        """
        Checks if a nonce is valid
        :param nonce: the nonce
        :return: if the nonce is valid
        """
        ...


class DefaultDPoPNonceCache(DPoPNonceCache):
    """
    A default implementation of a DPoPNonceCache utilizing an LRUCache
    """
    DEFAULT_CACHE_CAPACITY = 100

    def __init__(self, capacity: int = DEFAULT_CACHE_CAPACITY):
        self.lru_cache = LRUCache[str, str](capacity)

    def __getitem__(self, origin: str) -> str:
        return self.lru_cache.get(origin)

    def __setitem__(self, origin: str, nonce: str):
        self.lru_cache.set(origin, nonce)


class DefaultDPoPNonceGenerator(DPoPNonceGenerator):
    """
    A default implementation of a DPoPNonceGenerator
    """
    DEFAULT_MAX_AGE = 3 * 60  # 3 minutes

    def __init__(self, max_age: int = DEFAULT_MAX_AGE):
        self.interval = max_age / 3
        self.counter = self._current_counter()
        self.prev_nonce = self._compute(self.counter - 1)
        self.cur_nonce = self._compute(self.counter)
        self.next_nonce = self._compute(self.counter + 1)
        self.lock = Lock()

    def next(self) -> str:
        self._rotate()
        return self.next_nonce

    def check(self, nonce: str) -> bool:
        return self.next_nonce == nonce or self.cur_nonce == nonce or self.prev_nonce == nonce

    def _current_counter(self) -> int:
        return int(time.time() / self.interval)

    def _rotate(self):
        with self.lock:
            counter = self._current_counter()
            match counter - self.counter:
                case 0:
                    pass
                case 1:
                    self.prev_nonce = self.cur_nonce
                    self.cur_nonce = self.next_nonce
                    self.next_nonce = self._compute(counter + 1)
                case 2:
                    self.prev_nonce = self.next_nonce
                    self.cur_nonce = self._compute(counter)
                    self.next_nonce = self._compute(counter + 1)
                case 3:
                    self.prev_nonce = self._compute(counter - 1)
                    self.cur_nonce = self._compute(counter)
                    self.next_nonce = self._compute(counter + 1)
            self.counter = counter

    @staticmethod
    def _compute(counter: int) -> str:
        return generate_token()
