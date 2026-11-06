import types

import pytest

from authlib.common.hooks import Hookable
from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749.hooks import hooked


class Service(Hookable):
    def compute(self, x):
        return x * 2

    @staticmethod
    def static(x):
        return x

    @classmethod
    def klass(cls, x):
        return x

    @property
    def prop(self):
        return 1


def test_before_after_replace_hooks():
    """Hooks run before, after, and instead of any method."""
    svc = Service()
    calls = []
    svc.register_hook(
        lambda instance, x: calls.append(("before", x)), before=Service.compute
    )
    svc.register_hook(
        lambda instance, r: calls.append(("after", r)), after=Service.compute
    )
    svc.register_hook(
        lambda instance, original, x: original(x) + 10, replace=svc.compute
    )

    assert svc.compute(3) == 16
    assert calls == [("before", 3), ("after", 16)]


def test_hook_names():
    """Hooks can be registered with a hook name."""
    svc = Service()
    results = []
    svc.register_hook("after_compute", lambda instance, r: results.append(r))
    svc.register_hook("replace_compute", lambda instance, original, x: original(x) + 1)

    assert svc.compute(3) == 7
    assert results == [7]


def test_hook_names_on_attributes_that_cannot_be_hooked():
    """A hook name on an attribute that cannot be hooked raises an error."""
    svc = Service()

    def hook(instance, *args):
        pass

    for name in ("after_static", "after_klass", "before_prop", "replace_register_hook"):
        with pytest.raises(TypeError, match="cannot hook"):
            svc.register_hook(name, hook)

    svc.register_hook("after_custom_event", hook)
    svc.execute_hook("after_custom_event")


def test_hooks_run_in_registration_order():
    """Hooks run in the order they are registered."""

    class ListService(Hookable):
        def compute(self, x):
            return [x]

    svc = ListService()
    calls = []
    for i in range(10):
        svc.register_hook(
            lambda instance, r, i=i: calls.append(i), after=ListService.compute
        )
        svc.register_hook(
            lambda instance, original, x, i=i: original(x) + [i],
            replace=ListService.compute,
        )

    assert svc.compute(0) == [0] + list(range(10))
    assert calls == list(range(10))


def test_hooks_on_override():
    """Hooks registered with a parent reference run on an override."""

    class SubService(Service):
        def compute(self, x):
            return x * 3

    svc = SubService()
    results = []
    svc.register_hook(lambda instance, r: results.append(r), after=Service.compute)

    assert svc.compute(3) == 9
    assert results == [9]


def test_hooks_run_once_with_super():
    """Hooks run once around an override that calls super()."""

    class SubService(Service):
        def compute(self, x):
            return super().compute(x) + 1

    svc = SubService()
    results = []
    svc.register_hook(lambda instance, r: results.append(r), after=Service.compute)

    assert svc.compute(3) == 7
    assert results == [7]


def test_hooks_on_mixin_method():
    """Methods of a Hookable mixin can be hooked, and the mixin is not copied."""

    class Mixin(Hookable):
        def mixed(self):
            return "mixed"

    class MixedService(Service, Mixin):
        pass

    svc = MixedService()
    svc.register_hook(lambda instance, original: original() + "!", replace=Mixin.mixed)

    assert svc.mixed() == "mixed!"
    assert "mixed" not in vars(MixedService)


def test_mixin_method_that_is_not_hookable():
    """Methods of a mixin that is not Hookable cannot be hooked."""

    class Mixin:
        def mixed(self):
            return "mixed"

    original = Mixin.mixed

    class MixedService(Hookable, Mixin):
        pass

    svc = MixedService()
    with pytest.raises(TypeError, match="cannot hook"):
        svc.register_hook(lambda instance, r: None, after=Mixin.mixed)
    with pytest.raises(TypeError, match="cannot hook"):
        svc.register_hook("after_mixed", lambda instance, r: None)

    assert Mixin.mixed is original
    assert "mixed" not in vars(MixedService)
    assert svc.mixed() == "mixed"


def test_mixin_override_of_a_hooked_method():
    """A mixin that is not Hookable can override a hooked method."""

    class Mixin:
        def compute(self, x):
            return x * 5

    class MixedService(Mixin, Service):
        pass

    svc = MixedService()
    results = []
    svc.register_hook(lambda instance, r: results.append(r), after=Service.compute)

    assert svc.compute(3) == 15
    assert results == [15]
    assert Mixin.compute(svc, 3) == 15


def test_hooks_on_aliased_method():
    """Hooks run on a method assigned under another name."""

    def triple(self, x):
        return x * 3

    class AliasService(Service):
        compute = triple

    svc = AliasService()
    results = []
    svc.register_hook(lambda instance, r: results.append(r), after=Service.compute)
    svc.register_hook(lambda instance, r: results.append(r), after=svc.compute)

    assert svc.compute(3) == 9
    assert results == [9, 9]


def test_hooks_on_replaced_method():
    """Hooks run once when a method is replaced after the class is created."""

    class MidService(Service):
        def compute(self, x):
            return super().compute(x) + 1

    class LeafService(MidService):
        pass

    original = MidService.compute
    LeafService.compute = lambda self, x: original(self, x) + 100

    svc = LeafService()
    results = []
    svc.register_hook(lambda instance, r: results.append(r), after=Service.compute)

    assert svc.compute(3) == 107
    assert results == [7]


def test_hooked_method_called_with_another_object():
    """A wrapped method called through the class with another object runs as is."""
    assert Service.compute(types.SimpleNamespace(), 3) == 6


def test_hooks_are_per_instance():
    """Hooks only run for the instance they are registered on."""
    svc = Service()
    other = Service()
    svc.register_hook(lambda instance, original, x: 0, replace=Service.compute)

    assert svc.compute(3) == 0
    assert other.compute(3) == 6


def test_methods_without_hooks_keep_working():
    """Static methods, class methods and properties are not wrapped."""
    svc = Service()

    assert svc.static(1) == 1
    assert svc.klass(1) == 1
    assert Service.klass(1) == 1
    assert svc.prop == 1


def test_register_hook_invalid_arguments():
    """register_hook rejects methods that cannot be hooked and invalid arguments."""
    svc = Service()

    def hook(instance, r):
        pass

    class Other(Hookable):
        def compute(self, x):
            return x

    class Falsy:
        def __bool__(self):
            return False

    for method in (
        Service.static,
        Service.klass,
        Service.__init__,
        hook,
        Other.compute,
        Falsy(),
    ):
        with pytest.raises(TypeError, match="cannot hook"):
            svc.register_hook(hook, after=method)
    with pytest.raises(TypeError, match="exactly one"):
        svc.register_hook(hook)
    with pytest.raises(TypeError, match="exactly one"):
        svc.register_hook(hook, before=Service.compute, after=Service.compute)
    with pytest.raises(TypeError, match="exactly one"):
        svc.register_hook(hook, hook, after=Service.compute)
    with pytest.raises(TypeError, match="followed by the hook only"):
        svc.register_hook("after_compute")
    with pytest.raises(TypeError, match="followed by the hook only"):
        svc.register_hook("after_compute", hook, after=Service.compute)


def test_hooked_is_deprecated():
    """The hooked decorator warns and leaves the method unchanged."""
    with pytest.warns(AuthlibDeprecationWarning, match="1.11"):

        class DecoratedService(Hookable):
            @hooked
            def compute(self, x):
                return x * 2

            @hooked()
            def other(self, x):
                return x

    svc = DecoratedService()
    results = []
    svc.register_hook(lambda instance, r: results.append(r), after=svc.compute)

    assert svc.compute(3) == 6
    assert svc.other(3) == 3
    assert results == [6]


def test_hooked_rejects_custom_names():
    """The hooked decorator does not support custom hook names anymore."""
    with (
        pytest.warns(AuthlibDeprecationWarning),
        pytest.raises(TypeError, match="custom hook names"),
    ):
        hooked(after="after_custom")
