"""Detection and preparation of native Windows redistributables.

A portable folder is not made self-contained merely by putting the main EXE in
``App``.  Native programs load DLLs by name and Windows does not ship every
legacy DirectX or Visual C++ runtime.  This module deliberately does not fake a
DLL: it reads the PE import table, records every known runtime dependency, and
copies a matching app-local DLL only when a real file is available.

The catalog is also used to create an offline, auditable redistributable
manifest.  The packages are not downloaded silently and are never installed on
the builder machine.  That keeps the portable build side-effect free while
still covering the old VC++ 2005--2013, current VC++ and legacy DirectX
families which cause the usual ``MSVCP110.dll``/``XINPUT1_3.dll`` errors.
"""
from __future__ import annotations

import json
import mmap
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class RedistributablePackage:
    """One official runtime family and its download/documentation pages."""

    package_id: str
    display_name: str
    family: str
    dll_patterns: Tuple[str, ...]
    official_page: str
    architectures: Tuple[str, ...] = ("x86", "x64")
    installer_names: Tuple[str, ...] = ()
    silent_args: Tuple[str, ...] = ("/install", "/quiet", "/norestart")


# These are deliberately package *pages*, not third-party mirrors.  A user can
# put the downloaded official installer next to an input setup or in App and
# Portablizer will carry it into the generated Redistributables directory.
RUNTIME_PACKAGES: Tuple[RedistributablePackage, ...] = (
    RedistributablePackage(
        "vc2003-legacy", "Visual C++ 7.0/7.1 legacy app-local runtime",
        "visual-cpp-legacy",
        (r"^(?:msvcp|msvcr)7[01](?:_.*)?\.dll$",),
        "https://learn.microsoft.com/cpp/windows/determining-which-dlls-to-redistribute",
        installer_names=(),
    ),
    RedistributablePackage(
        "vc2005", "Microsoft Visual C++ 2005 SP1 Redistributable",
        "visual-cpp", (r"^(?:msvcp|msvcr|msvcm|mfc|atl|vcomp)80(?:_.*)?\.dll$",),
        "https://www.microsoft.com/download/details.aspx?id=5638",
        installer_names=("vcredist_x86.exe", "vcredist_x64.exe"),
        silent_args=("/q", "/norestart"),
    ),
    RedistributablePackage(
        "vc2008", "Microsoft Visual C++ 2008 SP1 Redistributable",
        "visual-cpp", (r"^(?:msvcp|msvcr|msvcm|mfc|atl|vcomp)90(?:_.*)?\.dll$",),
        "https://www.microsoft.com/download/details.aspx?id=5582",
        installer_names=("vcredist_x86.exe", "vcredist_x64.exe"),
        silent_args=("/q", "/norestart"),
    ),
    RedistributablePackage(
        "vc2010", "Microsoft Visual C++ 2010 SP1 Redistributable",
        "visual-cpp", (r"^(?:msvcp|msvcr|msvcm|mfc|atl|vcomp)100(?:_.*)?\.dll$",),
        "https://www.microsoft.com/download/details.aspx?id=26999",
        installer_names=("vcredist_x86.exe", "vcredist_x64.exe"),
        silent_args=("/q", "/norestart"),
    ),
    RedistributablePackage(
        "vc2012", "Microsoft Visual C++ 2012 Update 4 Redistributable",
        "visual-cpp", (r"^(?:msvcp|msvcr|msvcm|mfc|atl|vcomp)110(?:_.*)?\.dll$",),
        "https://www.microsoft.com/download/details.aspx?id=30679",
        installer_names=("vcredist_x86.exe", "vcredist_x64.exe"),
        silent_args=("/install", "/quiet", "/norestart"),
    ),
    RedistributablePackage(
        "vc2013", "Microsoft Visual C++ 2013 Redistributable",
        "visual-cpp", (r"^(?:msvcp|msvcr|msvcm|mfc|atl|vcomp|vccorlib)120(?:_.*)?\.dll$",),
        "https://www.microsoft.com/download/details.aspx?id=40784",
        installer_names=("vcredist_x86.exe", "vcredist_x64.exe"),
        silent_args=("/install", "/quiet", "/norestart"),
    ),
    RedistributablePackage(
        "vc2015-2022", "Microsoft Visual C++ Redistributable 2015--2022",
        "visual-cpp", (
            r"^(?:msvcp|msvcr|msvcm|mfc|atl|vcomp|vcruntime|concrt|vccorlib)14(?:[0-9_].*)?\.dll$",
            r"^(?:api-ms-win-crt|ucrtbase).*\.dll$",
        ),
        "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
        architectures=("x86", "x64", "arm64"),
        installer_names=("vc_redist.x86.exe", "vc_redist.x64.exe", "vc_redist.arm64.exe"),
    ),
    RedistributablePackage(
        "directx-legacy-jun2010", "DirectX End-User Runtime (June 2010)",
        "directx-legacy", (
            r"^d3dx(?:9|10|11)_.*\.dll$", r"^d3dcompiler_.*\.dll$",
            r"^d3dcsx_.*\.dll$", r"^xinput.*\.dll$",
            r"^x3daudio.*\.dll$", r"^xaudio2_.*\.dll$",
            r"^xactengine.*\.dll$", r"^xapofx.*\.dll$",
        ),
        "https://www.microsoft.com/download/details.aspx?id=8109",
        architectures=("x86", "x64"),
        installer_names=("directx_Jun2010_redist.exe", "dxwebsetup.exe", "DXSETUP.exe"),
        silent_args=("/Q",),
    ),
)

_PACKAGE_BY_ID = {item.package_id: item for item in RUNTIME_PACKAGES}

# Windows DLLs which are deliberately not treated as redistributable payloads.
# They are provided by the operating system or by the application itself.
_SYSTEM_DLLS = {
    "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll",
    "ws2_32.dll", "winmm.dll", "version.dll", "ntdll.dll", "bcrypt.dll",
    "imm32.dll", "setupapi.dll", "shlwapi.dll", "rpcrt4.dll", "secur32.dll",
}


def _normal_name(name: str) -> str:
    return os.path.basename(str(name).replace("\\", "/")).strip().casefold()


def _package_for_name(name: str) -> Optional[RedistributablePackage]:
    normalized = _normal_name(name)
    if not normalized or normalized in _SYSTEM_DLLS:
        return None
    for package in RUNTIME_PACKAGES:
        if any(re.match(pattern, normalized, flags=re.IGNORECASE)
               for pattern in package.dll_patterns):
            return package
    return None


def package_for_dll(name: str) -> Optional[RedistributablePackage]:
    """Public lookup used by diagnostics and tests."""
    return _package_for_name(name)


def _rva_to_offset(rva: int, sections: Sequence[Tuple[int, int, int, int]]) -> Optional[int]:
    for virtual, span, raw, raw_size in sections:
        if virtual <= rva < virtual + span:
            delta = rva - virtual
            if delta >= raw_size:
                return None
            return raw + delta
    return None


def _read_pe_imports(data: memoryview) -> Tuple[Optional[str], List[str]]:
    """Read machine type and imported DLL names from a PE image."""
    if len(data) < 0x40 or bytes(data[:2]) != b"MZ":
        return None, []
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 0 or pe_offset + 24 > len(data) \
            or bytes(data[pe_offset:pe_offset + 4]) != b"PE\0\0":
        return None, []
    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
    architecture = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine)
    sections_count = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
    optional_size = int.from_bytes(data[pe_offset + 20:pe_offset + 22], "little")
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 96:
        return architecture, []
    magic = int.from_bytes(data[optional:optional + 2], "little")
    if magic not in (0x10B, 0x20B):
        return architecture, []
    # IMAGE_OPTIONAL_HEADER.DataDirectory starts at 96 for PE32 and PE32+.
    directory = optional + 96 + 8  # index 1 = IMAGE_DIRECTORY_ENTRY_IMPORT
    if directory + 8 > optional + optional_size:
        return architecture, []
    import_rva = int.from_bytes(data[directory:directory + 4], "little")
    # IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT is index 13.  A DLL such as XInput
    # is often delay-loaded by games, so looking only at the normal import
    # directory would miss exactly the dependency this diagnostic is meant to
    # catch.
    delay_directory = optional + 96 + 13 * 8
    delay_rva = 0
    if delay_directory + 8 <= optional + optional_size:
        delay_rva = int.from_bytes(data[delay_directory:delay_directory + 4], "little")

    section_table = optional + optional_size
    sections: List[Tuple[int, int, int, int]] = []
    for index in range(sections_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        virtual_size = int.from_bytes(data[offset + 8:offset + 12], "little")
        virtual = int.from_bytes(data[offset + 12:offset + 16], "little")
        raw_size = int.from_bytes(data[offset + 16:offset + 20], "little")
        raw = int.from_bytes(data[offset + 20:offset + 24], "little")
        if raw and raw < len(data):
            sections.append((virtual, max(virtual_size, raw_size), raw, raw_size))
    def directory_names(directory_rva: int, delayed: bool = False) -> List[str]:
        descriptor = _rva_to_offset(directory_rva, sections)
        if descriptor is None:
            return []
        names: List[str] = []
        # PE32/PE32+ image base is needed only for the uncommon VA-form delay
        # import table.  The usual table stores RVAs directly.
        image_base_offset = 28 if magic == 0x10B else 24
        image_base_size = 4 if magic == 0x10B else 8
        image_base = int.from_bytes(
            data[optional + image_base_offset:
                 optional + image_base_offset + image_base_size],
            "little",
        )
        for index in range(4096):
            current = descriptor + index * 20
            if current + 20 > len(data):
                break
            values = [int.from_bytes(data[current + i:current + i + 4], "little")
                      for i in range(0, 20, 4)]
            if not any(values):
                break
            name_rva = values[1] if delayed else values[3]
            name_offset = _rva_to_offset(name_rva, sections)
            if name_offset is None and delayed and image_base and name_rva >= image_base:
                name_offset = _rva_to_offset(name_rva - image_base, sections)
            if name_offset is None or name_offset >= len(data):
                continue
            end = name_offset
            while end < len(data) and end - name_offset < 512 and data[end]:
                end += 1
            try:
                name = bytes(data[name_offset:end]).decode("ascii")
            except UnicodeDecodeError:
                continue
            if name:
                names.append(_normal_name(name))
        return names

    imports = directory_names(import_rva)
    if delay_rva:
        imports.extend(directory_names(delay_rva, delayed=True))
    return architecture, sorted(set(imports))


def read_pe_imports(path: str | os.PathLike[str]) -> Tuple[Optional[str], List[str]]:
    """Return ``(architecture, imported_dlls)`` without a third-party package."""
    try:
        with open(path, "rb") as handle:
            if not handle.seekable() or os.fstat(handle.fileno()).st_size == 0:
                return None, []
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                return _read_pe_imports(memoryview(mapped))
    except (OSError, ValueError):
        return None, []


@dataclass
class RuntimeReport:
    """Serializable dependency inventory for one generated portable folder."""

    files_scanned: int = 0
    architectures: List[str] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    required: List[str] = field(default_factory=list)
    provided: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    copied: Dict[str, str] = field(default_factory=dict)
    packages: Dict[str, Dict[str, object]] = field(default_factory=dict)
    bundled_installers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "files_scanned": self.files_scanned,
            "architectures": self.architectures,
            "imports": self.imports,
            "required": self.required,
            "provided": self.provided,
            "missing": self.missing,
            "copied": self.copied,
            "packages": self.packages,
            "bundled_installers": self.bundled_installers,
            "warnings": self.warnings,
        }


def inspect_application(app_dir: str | os.PathLike[str]) -> RuntimeReport:
    """Inspect every PE in ``App`` and list known runtime imports."""
    root = Path(app_dir)
    report = RuntimeReport()
    all_files: List[Path] = []
    provided: Dict[str, str] = {}
    if root.is_dir():
        for current, _dirs, files in os.walk(root):
            for filename in files:
                path = Path(current) / filename
                if filename.casefold().endswith((".exe", ".dll")):
                    all_files.append(path)
                if filename.casefold().endswith(".dll"):
                    provided.setdefault(_normal_name(filename),
                                        str(path.relative_to(root)).replace("\\", "/"))
    report.files_scanned = len(all_files)
    report.provided = dict(sorted(provided.items()))

    architectures: Set[str] = set()
    required: Set[str] = set()
    for path in all_files:
        architecture, imports = read_pe_imports(path)
        if architecture:
            architectures.add(architecture)
        if imports:
            report.imports[str(path.relative_to(root)).replace("\\", "/")] = imports
        for name in imports:
            if _package_for_name(name):
                required.add(name)
    report.architectures = sorted(architectures)
    report.required = sorted(required)
    report.missing = sorted(name for name in required if name not in provided)

    package_dlls: Dict[str, List[str]] = {}
    for name in report.required:
        package = _package_for_name(name)
        if package:
            package_dlls.setdefault(package.package_id, []).append(name)
    for package_id, dlls in sorted(package_dlls.items()):
        package = _PACKAGE_BY_ID[package_id]
        report.packages[package_id] = {
            "display_name": package.display_name,
            "family": package.family,
            "required_dlls": sorted(dlls),
            "missing_dlls": sorted(name for name in dlls if name in report.missing),
            "architectures": list(package.architectures),
            "official_page": package.official_page,
            "installer_names": list(package.installer_names),
        }
    return report


def _candidate_names(name: str) -> Iterable[str]:
    # A Windows file system is case insensitive, while tests and development
    # builds often run on Linux.  Try both exact spelling and a case-folded walk.
    yield name
    lower = name.casefold()
    if lower != name:
        yield lower


def _find_in_roots(
    name: str, roots: Sequence[str], expected_architecture: Optional[str] = None,
) -> Optional[Path]:
    def acceptable(candidate: Path) -> bool:
        if not candidate.is_file():
            return False
        if expected_architecture:
            source_arch, _imports = read_pe_imports(candidate)
            if source_arch and source_arch != expected_architecture:
                return False
        return True

    for root_name in roots:
        root = Path(root_name)
        if not root.is_dir():
            continue
        for candidate_name in _candidate_names(name):
            candidate = root / candidate_name
            if acceptable(candidate):
                return candidate
        # Runtime packages are commonly in a redist subdirectory.  Limit the
        # walk to four levels and compare names case-insensitively.
        try:
            for current, dirs, files in os.walk(root):
                relative_depth = len(Path(current).relative_to(root).parts)
                if relative_depth >= 4:
                    dirs[:] = []
                for filename in files:
                    if filename.casefold() == name.casefold():
                        candidate = Path(current) / filename
                        if acceptable(candidate):
                            return candidate
        except OSError:
            continue
    return None


def _system_runtime_roots(architecture: str) -> List[str]:
    if not os.name == "nt":
        return []
    windows = os.environ.get("WINDIR", r"C:\Windows")
    if architecture == "x86":
        names = ("SysWOW64", "System32")
    else:
        names = ("System32", "Sysnative")
    return [os.path.join(windows, name) for name in names]


def copy_available_runtime_dlls(
    report: RuntimeReport,
    app_dir: str | os.PathLike[str],
    extra_roots: Sequence[str] = (),
) -> Dict[str, str]:
    """Copy real matching runtime DLLs into ``App/Runtime/<architecture>``.

    Only names already present in the import table are copied.  The PE machine
    type is checked when possible so an x64 runtime can never be put beside an
    x86 program by accident.  ``extra_roots`` is useful for a setup's local
    ``redist`` directory and makes this function straightforward to test.
    """
    root = Path(app_dir)
    copied: Dict[str, str] = {}
    architectures = report.architectures or ["x86", "x64"]
    search_roots = [str(item) for item in extra_roots]
    for architecture in architectures:
        search_roots.extend(_system_runtime_roots(architecture))

    expected_architecture = architecture_for_name(report, "")
    for name in list(report.missing):
        source = _find_in_roots(
            name, search_roots, expected_architecture=expected_architecture
        )
        if source is None:
            continue
        destination_dir = root / "Runtime" / (architecture_for_name(report, name) or "native")
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / name
        try:
            if source.resolve() != destination.resolve():
                shutil.copy2(source, destination)
            copied[name] = str(destination.relative_to(root)).replace("\\", "/")
        except OSError:
            continue
    report.copied.update(copied)
    return copied


def architecture_for_name(report: RuntimeReport, _name: str) -> Optional[str]:
    """Choose the only PE architecture when it is unambiguous."""
    if len(report.architectures) == 1:
        return report.architectures[0]
    # A mixed application normally runs the main x86/x64 executable.  Keeping
    # the neutral directory prevents an incorrect guess; PATH still finds it.
    return None


def find_bundled_installers(app_dir: str | os.PathLike[str]) -> List[str]:
    """Find known Microsoft redistributable installers already supplied by App."""
    root = Path(app_dir)
    found: List[str] = []
    if not root.is_dir():
        return found
    pattern = re.compile(
        r"^(?:vc_redist(?:\.(?:x86|x64|arm64))?|vcredist(?:_x86|_x64)?|"
        r"directx_Jun2010_redist|dxwebsetup|DXSETUP)\.exe$", re.IGNORECASE)
    for current, _dirs, files in os.walk(root):
        for filename in files:
            if pattern.match(filename):
                found.append(str((Path(current) / filename).relative_to(root)).replace("\\", "/"))
    return sorted(set(found), key=str.casefold)


def render_runtime_script(report: RuntimeReport) -> str:
    """Create a safe ASCII cmd helper for installers present in the output."""
    lines = [
        "@echo off",
        "setlocal",
        "rem Portablizer redistributable helper; run only when the app needs it.",
        "set \"ROOT=%~dp0\"",
        "",
    ]
    for relative in report.bundled_installers:
        package_id = ""
        name = Path(relative).name.casefold()
        if "dx" in name or "directx" in name:
            package_id = "directx-legacy-jun2010"
        elif "2010" in name:
            package_id = "vc2010"
        elif "2012" in name:
            package_id = "vc2012"
        elif "2013" in name:
            package_id = "vc2013"
        package = _PACKAGE_BY_ID.get(package_id)
        if package:
            args = package.silent_args
        elif name.startswith("vcredist"):
            # The 2005--2013 installers use the older /q switch; unlike the
            # v14 bundle they do not consistently accept /install.
            args = ("/q", "/norestart")
        else:
            args = ("/install", "/quiet", "/norestart")
        rel = relative.replace("/", "\\")
        arg_text = " ".join(args)
        lines.extend([
            f"echo Installing {Path(relative).name}...",
            f'start "" /wait "%ROOT%{rel}" {arg_text}',
            "if errorlevel 1 echo WARNING: installer returned %ERRORLEVEL%.",
            "",
        ])
    if not report.bundled_installers:
        # The user can add an official package after the portable folder was
        # created.  Keep the helper useful without turning it into a wildcard
        # launcher for arbitrary EXE files.
        lines.extend([
            "echo No installer was supplied by the original setup.",
            "echo Looking for official packages added to Redistributables...",
            "for %%F in (\"%ROOT%Redistributables\\vc_redist*.exe\" \"%ROOT%Redistributables\\vcredist*.exe\") do if exist \"%%~fF\" start \"\" /wait \"%%~fF\" /install /quiet /norestart",
            "for %%F in (\"%ROOT%Redistributables\\directx_Jun2010_redist.exe\" \"%ROOT%Redistributables\\dxwebsetup.exe\" \"%ROOT%Redistributables\\DXSETUP.exe\") do if exist \"%%~fF\" start \"\" /wait \"%%~fF\" /Q",
            "echo Read runtime-manifest.json and README_Redistributables.txt.",
            "exit /b 2",
        ])
    else:
        lines.extend([
            "echo Redistributable installers finished.",
            "exit /b 0",
        ])
    return "\r\n".join(lines) + "\r\n"


def render_runtime_readme(report: RuntimeReport) -> str:
    missing = ", ".join(report.missing) if report.missing else "нет"
    copied = ", ".join(f"{name} -> {path}" for name, path in report.copied.items()) or "нет"
    lines = [
        "REDISTRIBUTABLES / НАТИВНЫЕ ЗАВИСИМОСТИ",
        "=" * 58,
        "",
        "Portablizer прочитал таблицу импортов PE у всех EXE и DLL в App.",
        "Это не угадывание по имени файла: ниже перечислены реальные DLL,",
        "которые программа запрашивает при запуске.",
        "",
        f"Обнаруженные runtime DLL: {', '.join(report.required) or 'нет'}",
        f"Не найденные рядом с программой: {missing}",
        f"Скопированные совместимые DLL: {copied}",
        "",
        "Поддержанные семейства Microsoft:",
        "  Visual C++ 2005, 2008, 2010, 2012, 2013, 2015-2022 (x86/x64)",
        "  DirectX End-User Runtime June 2010 (D3DX, XInput, XAudio2)",
        "",
        "Если не найденных DLL нет — этот отчёт только для справки.",
        "Если они есть, запустите Install_Redistributables.cmd после того,",
        "как положите официальные установщики Microsoft в App/Redist или",
        "Redistributables. Либо установите соответствующий пакет вручную",
        "со страницы official_page в runtime-manifest.json.",
        "",
        "Установка runtime изменяет Windows и может потребовать UAC.",
        "Portablizer не запускает её автоматически и не подменяет DLL-заглушками.",
        "",
    ]
    for package in report.packages.values():
        lines.append(f"{package['display_name']}: {package['official_page']}")
    return "\r\n".join(lines) + "\r\n"


def render_runtime_manifest(report: RuntimeReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"
