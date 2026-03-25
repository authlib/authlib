from collections import defaultdict


class Hookable:
    _hooks = None

    def __init__(self):
        self._hooks = defaultdict(set)

    def register_hook(self, hook_type, hook):
        self._hooks[hook_type].add(hook)

    def execute_hook(self, hook_type, *args, **kwargs):
        for hook in self._hooks[hook_type]:
            hook(self, *args, **kwargs)


def hooked(func=None, before=None, after=None, replace=None):
    """Execute hooks before, after, or instead of the decorated method.

    A ``replace`` hook receives ``(instance, original, *args, **kwargs)``
    where ``original`` is a callable that invokes the original method::

        def my_wrapper(instance, original, *args, **kwargs):
            result = original(*args, **kwargs)
            return result


        hookable.register_hook("replace_validate_request", my_wrapper)
    """

    def decorator(func):
        before_name = before or f"before_{func.__name__}"
        after_name = after or f"after_{func.__name__}"
        replace_name = replace or f"replace_{func.__name__}"

        def wrapper(self, *args, **kwargs):
            self.execute_hook(before_name, *args, **kwargs)

            replacements = list(self._hooks.get(replace_name, []))
            if replacements:

                def initial_call(*a, **kw):
                    return func(self, *a, **kw)

                def chain(hook, prev):
                    def call(*a, **kw):
                        return hook(self, prev, *a, **kw)

                    return call

                effective_call = initial_call
                for hook in replacements:
                    effective_call = chain(hook, effective_call)
            else:

                def effective_call(*a, **kw):
                    return func(self, *a, **kw)

            result = effective_call(*args, **kwargs)
            self.execute_hook(after_name, result)
            return result

        return wrapper

    # The decorator has been called without parenthesis
    if callable(func):
        return decorator(func)

    return decorator
