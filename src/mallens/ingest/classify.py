from __future__ import annotations
from mallens.core.datatypes import ClassKind

# this returns the class kind, a framework, library, or spoofed
# 
class ClassClassifier:
    def __init__(self, framework_prefixes, library_prefixes,
                 bundled_ok_prefixes: tuple[str, ...] = (),
                 internal_names: set[str] | None = None,):
        self._fw = tuple(sorted(framework_prefixes, key=len, reverse=True))
        self._lib = tuple(sorted(library_prefixes, key=len, reverse=True))
        self._internal = internal_names or set()
        self._bundled_ok = tuple(bundled_ok_prefixes)

    def _prefix_kind(self, class_name: str) -> ClassKind:
        for p in self._lib:
            if class_name.startswith(p):
                return ClassKind.LIBRARY
        for p in self._fw:
            if class_name.startswith(p):
                return ClassKind.FRAMEWORK
        return ClassKind.APP

    def kind_of(self, class_name: str) -> tuple[ClassKind, bool]:
        """Returns (kind, spoofed). Dex-residency overrides prefix:
        an internal class with a framework name is spoofed (MilkyDoor-style)
        UNLESS it belongs to a known legitimately-bundled namespace
        (support libs, kotlin runtime, desugared java, apache http, ...)."""
        kind = self._prefix_kind(class_name)
        if class_name in self._internal and kind is ClassKind.FRAMEWORK:
            if class_name.startswith(self._bundled_ok):
                return ClassKind.LIBRARY, False   # bundled lib, not spoofed
            return ClassKind.APP, True            # genuine masquerading
        return kind, False


# class ClassClassifier:
#     def __init__(self, framework_prefixes, library_prefixes,
#                  internal_names: set[str] | None = None):
#         self._fw = tuple(sorted(framework_prefixes, key=len, reverse=True))
#         self._lib = tuple(sorted(library_prefixes, key=len, reverse=True))
#         self._internal = internal_names or set()

#     def _prefix_kind(self, class_name: str) -> ClassKind:
#         for p in self._lib:
#             if class_name.startswith(p):
#                 return ClassKind.LIBRARY
#         for p in self._fw:
#             if class_name.startswith(p):
#                 return ClassKind.FRAMEWORK
#         return ClassKind.APP

#     def kind_of(self, class_name: str) -> tuple[ClassKind, bool]:
#         """Returns (kind, spoofed). Dex-residency overrides prefix:
#         an internal class with a framework name is APP + spoofed=True
#         (MilkyDoor-style injection). FRAMEWORK is only possible for
#         classes NOT in the dex."""
#         kind = self._prefix_kind(class_name)
#         if class_name in self._internal and kind is ClassKind.FRAMEWORK:
#             return ClassKind.APP, True
#         return kind, False

# the spoofing needs a valid and logical idea

# LEGIT_PREFIXES = (
#     "Landroid/support/", "Landroidx/", "Lkotlin/", "Lkotlinx/",
#     "Lj$/", "Lcom/google/", "Lorg/jetbrains/", "Lorg/intellij/",
#     "Ldalvik/", "Lorg/apache/",  # commons/http bundled everywhere
# )
# FRAMEWORK_PREFIXES = ("Landroid/", "Ljava/", "Ljavax/")

# def is_spoofed_framework(class_name: str) -> bool:
#     if class_name.startswith(LEGIT_PREFIXES):
#         return False
#     return class_name.startswith(FRAMEWORK_PREFIXES)


