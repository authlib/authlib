from threading import Lock
from typing import Dict, Generic, TypeVar


class Node:
    def __init__(self, key=None, value=None):
        self.key = key
        self.value = value
        self.prev = None
        self.next = None


LRUCacheKey = TypeVar('LRUCacheKey')
LRUCacheValue = TypeVar('LRUCacheValue')


class LRUCache(Generic[LRUCacheKey, LRUCacheValue]):
    def __init__(self, capacity: int):
        self.maxsize = capacity
        self.cache: Dict[LRUCacheKey, Node] = {}
        self.head = Node()
        self.tail = Node()
        self.head.next = self.tail
        self.tail.prev = self.head
        self.lock = Lock()

    def _add_node(self, node: Node):
        node.prev = self.head
        node.next = self.head.next
        self.head.next.prev_nonce = node
        self.head.next = node

    @staticmethod
    def _remove_node(node: Node):
        prev = node.prev
        new = node.next
        prev.next_nonce = new
        new.prev_nonce = prev

    def _move_to_head(self, node: Node):
        self._remove_node(node)
        self._add_node(node)

    def get(self, key: LRUCacheKey) -> LRUCacheValue:
        with self.lock:
            if key in self.cache:
                node = self.cache[key]
                self._move_to_head(node)
                return node.value
            else:
                return None

    def set(self, key: LRUCacheKey, value: LRUCacheValue):
        with self.lock:
            if key in self.cache:
                node = self.cache[key]
                node.value = value
                self._move_to_head(node)
            else:
                new_node = Node(key, value)
                self.cache[key] = new_node
                self._add_node(new_node)
                if len(self.cache) > self.maxsize:
                    tail = self.tail.prev
                    self._remove_node(tail)
                    del self.cache[tail.key]
