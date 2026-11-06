import functools
import inspect
import types
import weakref
from collections import defaultdict

_HOOKED_FUNCTIONS = weakref.WeakKeyDictionary()


class Hookable:
    """Let hooks run before, after, or instead of any method of a subclass.

    Static methods, class methods, properties and dunder methods cannot be
    hooked. A method defined in a mixin that is not Hookable cannot be hooked,
    unless it overrides a method of a Hookable class.
    """

    _hooks = None

    def __init__(self):
        self._hooks = defaultdict(dict)

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for name in dir(cls):
            if name.startswith("__") and name.endswith("__"):
                continue
            if name in Hookable.__dict__:
                continue
            method = inspect.getattr_static(cls, name, None)
            if not isinstance(method, types.FunctionType) or _is_hooked(method):
                continue
            if name in vars(cls) or _hooked_implementation(cls, name) is not None:
                setattr(cls, name, _hook_method(method, name))

    def register_hook(
        self, hook_or_name, hook=None, /, *, before=None, after=None, replace=None
    ):
        """Register a hook on a method.

        Pass the hook, and the method in ``before``, ``after`` or ``replace``::

            grant.register_hook(
                validate_code_verifier,
                after=AuthorizationCodeGrant.validate_token_request,
            )

        Or pass a hook name, such as ``"after_validate_token_request"``,
        and then the hook::

            grant.register_hook("after_validate_token_request", validate_code_verifier)

        A ``before`` hook receives ``(instance, *args, **kwargs)``.
        An ``after`` hook receives ``(instance, result)``.
        A ``replace`` hook receives ``(instance, original, *args, **kwargs)``,
        where ``original`` calls the method::

            def replace_hook(instance, original, *args, **kwargs):
                return original(*args, **kwargs)

        Hooks run in the order they are registered.
        When a method is overridden, the hooks run around the override.

        :param hook_or_name: The hook, or a hook name.
        :param hook: The hook, when the first argument is a hook name.
        :param before: The method the hook runs before.
        :param after: The method the hook runs after.
        :param replace: The method the hook runs instead of.
        :raises TypeError: If the method cannot be hooked,
            if it does not belong to the class of this object or to its parents,
            or if the arguments do not match one of the two forms.
        """
        targets = {"before": before, "after": after, "replace": replace}
        targets = {
            phase: method for phase, method in targets.items() if method is not None
        }

        if isinstance(hook_or_name, str):
            if hook is None or targets:
                raise TypeError("A hook name must be followed by the hook only.")
            phase, _, name = hook_or_name.partition("_")
            if (
                phase in ("before", "after", "replace")
                and inspect.getattr_static(type(self), name, None) is not None
                and _hooked_implementation(type(self), name) is None
            ):
                raise TypeError(f"{type(self).__qualname__} cannot hook {name!r}.")
            self._hooks[hook_or_name][hook] = None
            return

        if hook is not None or len(targets) != 1:
            raise TypeError("Pass exactly one of 'before', 'after' or 'replace'.")

        ((phase, method),) = targets.items()
        func = getattr(method, "__func__", method)
        name = _hooked_name(func) or getattr(func, "__name__", None)
        if (
            not name
            or not any(vars(cls).get(name) is func for cls in type(self).__mro__)
            or _hooked_implementation(type(self), name) is None
        ):
            raise TypeError(f"{type(self).__qualname__} cannot hook {method!r}.")

        self._hooks[f"{phase}_{name}"][hook_or_name] = None

    def execute_hook(self, hook_type, *args, **kwargs):
        for hook in list(self._hooks.get(hook_type, ())):
            hook(self, *args, **kwargs)


def _hook_method(func, name):
    """Wrap a method so that its hooks run before, after, or instead of it.

    The hooks only run in the most derived wrapper of the method.
    So they run once when an override calls super().
    They still run when the class attribute is replaced by an object
    that is not wrapped, such as a mock that calls the original method.
    """
    before_name = f"before_{name}"
    after_name = f"after_{name}"
    replace_name = f"replace_{name}"

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        hooks = getattr(self, "_hooks", None) or {}
        has_hooks = before_name in hooks or after_name in hooks or replace_name in hooks
        if not has_hooks or _hooked_implementation(type(self), name) is not wrapper:
            return func(self, *args, **kwargs)

        self.execute_hook(before_name, *args, **kwargs)

        def effective_call(*a, **kw):
            return func(self, *a, **kw)

        def chain(hook, prev):
            def call(*a, **kw):
                return hook(self, prev, *a, **kw)

            return call

        for hook in list(self._hooks.get(replace_name, ())):
            effective_call = chain(hook, effective_call)

        result = effective_call(*args, **kwargs)
        self.execute_hook(after_name, result)
        return result

    _HOOKED_FUNCTIONS[wrapper] = name
    return wrapper


def _hooked_name(method):
    """Return the attribute name of a method that runs hooks, or None."""
    func = getattr(method, "__func__", method)
    if not isinstance(func, types.FunctionType):
        return None
    return _HOOKED_FUNCTIONS.get(func)


def _is_hooked(method):
    """Tell whether a function or a bound method runs hooks."""
    return _hooked_name(method) is not None


def _hooked_implementation(cls, name):
    """Return the most derived wrapper of a method in the class hierarchy."""
    for klass in cls.__mro__:
        method = vars(klass).get(name)
        if _is_hooked(method):
            return method
    return None
