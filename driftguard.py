#!/usr/bin/env python3
"""
DriftGuard 6
Project-aware environment drift + build-failure prediction + source-impact intelligence.

Standard-library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
import hashlib
import html
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import struct
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Any

APP_VERSION = "5.0.0"
STATE_DIR = ".driftguard"
BASELINE_FILE = "baseline.json"
LAST_REPORT_FILE = "last_report.json"
HISTORY_FILE = "history.jsonl"
EVENTS_FILE = "events.jsonl"
CONFIG_FILE = "config.json"
INCIDENTS_FILE = "incidents.jsonl"
LOG_DIR = "logs"

DEFAULT_CONFIG = {
    "preflight_max_risk": 70,
    "watch_interval": 10,
    "max_scan_depth": 5,
    "max_source_files": 25000,
    "max_capture_bytes": 5000000,
    "incident_history_limit": 100,
    "max_native_artifacts": 120,
    "max_native_dependency_inspections": 30,
    "dependency_sample_limit": 250,
    "source_scan_depth": 8,
    "max_source_manifest_files": 4000,
    "max_source_hash_bytes": 8000000,
    "max_graph_source_components": 120,
    "validation_plan_limit": 5,
}

TRACKED_FILES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock",
    "Pipfile", "Pipfile.lock",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "CMakeLists.txt", "CMakePresets.json", "vcpkg.json", "conanfile.txt", "conanfile.py",
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "pom.xml", "gradle.properties",
    "global.json", "Directory.Build.props", "Directory.Build.targets",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
}

TRACKED_SUFFIXES = {".uproject", ".sln", ".csproj", ".vcxproj"}

TOOL_COMMANDS = {
    "python": [sys.executable, "--version"],
    "git": ["git", "--version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "cmake": ["cmake", "--version"],
    "gcc": ["gcc", "--version"],
    "clang": ["clang", "--version"],
    "cl": ["cl"],
    "msbuild": ["msbuild", "-version"],
    "rustc": ["rustc", "--version"],
    "cargo": ["cargo", "--version"],
    "go": ["go", "version"],
    "java": ["java", "-version"],
    "dotnet": ["dotnet", "--version"],
    "adb": ["adb", "version"],
    "nvcc": ["nvcc", "--version"],
    "vulkaninfo": ["vulkaninfo", "--summary"],
    "docker": ["docker", "--version"],
}

IMPORTANT_ENV = [
    "CC", "CXX", "CMAKE_GENERATOR", "JAVA_HOME", "DOTNET_ROOT",
    "CUDA_PATH", "VULKAN_SDK", "ANDROID_HOME", "ANDROID_SDK_ROOT",
    "VCPKG_ROOT", "CONAN_HOME", "UE_SDKS_ROOT",
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
DEDUCTIONS = {"critical": 35, "high": 15, "medium": 7, "low": 2, "info": 0}

IGNORE_DIRS = {
    ".git", STATE_DIR, "node_modules", ".venv", "venv", "dist", "build", "out",
    "__pycache__", ".idea", ".vs", "Binaries", "Intermediate", "DerivedDataCache",
    "Library", "Temp", "obj", "bin",
}


@dataclass
class Finding:
    severity: str
    category: str
    item: str
    baseline: str
    current: str
    message: str
    recommendation: str


@dataclass
class Requirement:
    capability: str
    status: str
    evidence: str
    recommendation: str
    severity: str = "high"


@dataclass
class LogSignature:
    signature_id: str
    ecosystem: str
    title: str
    severity: str
    patterns: Tuple[str, ...]
    causes: Tuple[str, ...]
    recommendation: str
    drift_terms: Tuple[str, ...] = ()


LOG_SIGNATURES: Tuple[LogSignature, ...] = (
    LogSignature(
        "python.module-missing", "python", "Python module is missing", "high",
        (r"ModuleNotFoundError:\s*No module named", r"ImportError:\s*No module named"),
        ("The active interpreter does not have a required dependency.", "The command is using a different virtual environment/interpreter than expected."),
        "Verify the interpreter path, activate the intended virtual environment, then reinstall from the pinned dependency manifest.",
        ("python", "requirements", "pyproject", "poetry", "pipfile"),
    ),
    LogSignature(
        "python.native-load", "python", "Python native extension failed to load", "high",
        (r"DLL load failed", r"undefined symbol:.*Py[A-Za-z_]", r"wrong ELF class", r"not a valid Win32 application"),
        ("A native wheel/module was built for a different Python ABI or architecture.", "A required runtime DLL/shared library is missing or incompatible."),
        "Rebuild/reinstall the native dependency for the active Python version and architecture; verify runtime-library and PATH resolution.",
        ("python", "architecture", "path", "visual studio", "gcc", "clang"),
    ),
    LogSignature(
        "python.syntax", "python", "Python source syntax is invalid", "high",
        (r"SyntaxError:\s", r"IndentationError:\s", r"TabError:\s"),
        ("A changed Python source file cannot be parsed by the active interpreter.",),
        "Inspect the first reported file/line, correct the syntax or indentation error, then rerun the targeted test/compile validation.",
        ("python", "source", "project"),
    ),
    LogSignature(
        "node.resolve", "node", "Node dependency resolution failed", "high",
        (r"npm ERR!.*ERESOLVE", r"ERR_PNPM_PEER_DEP_ISSUES", r"YN0002|YN0060"),
        ("Peer-dependency constraints are incompatible.", "The lockfile/package-manager state may have changed."),
        "Restore the expected lockfile/package-manager version and resolve the conflicting dependency constraints instead of forcing an incompatible tree.",
        ("package.json", "lock", "node", "npm"),
    ),
    LogSignature(
        "node.engine", "node", "Node engine/version mismatch", "high",
        (r"EBADENGINE", r"Unsupported engine", r"The engine .* is incompatible with this module"),
        ("The active Node.js version is outside a package's supported range.",),
        "Switch to the project's expected Node.js version and reinstall dependencies from the lockfile.",
        ("node", "package.json"),
    ),
    LogSignature(
        "node.syntax", "node", "JavaScript source syntax is invalid", "high",
        (r"SyntaxError:\s*(?:Unexpected|Invalid|missing|Identifier)", r"SyntaxError:\s*Unexpected end of input"),
        ("A changed JavaScript source file cannot be parsed by the active Node.js runtime.",),
        "Inspect the first reported source location, correct the syntax error, then rerun the targeted npm/node validation.",
        ("node", "javascript", "source", "project"),
    ),
    LogSignature(
        "cmake.compiler", "cpp", "CMake cannot find or validate a compiler", "critical",
        (r"No CMAKE_CXX_COMPILER could be found", r"No CMAKE_C_COMPILER could be found", r"CMAKE_(?:C|CXX)_COMPILER.*not.*found", r"The C\+\+ compiler identification is unknown"),
        ("The compiler toolchain is missing or no longer on PATH.", "A generator/toolchain file points to a compiler that moved or was removed."),
        "Restore/select MSVC, GCC, or Clang, delete stale CMake cache if appropriate, then regenerate the build directory.",
        ("cmake", "compiler", "cl", "gcc", "clang", "path", "visual studio"),
    ),
    LogSignature(
        "cmake.package", "cpp", "CMake dependency/package discovery failed", "high",
        (r"Could not find a package configuration file provided by", r"Could NOT find [A-Za-z0-9_+.-]+", r"find_package.*could not find"),
        ("A development package/SDK is missing.", "CMAKE_PREFIX_PATH, vcpkg, Conan, or another package root changed."),
        "Restore the expected dependency manager/SDK path and regenerate CMake with the project's known-good toolchain configuration.",
        ("cmake", "vcpkg", "conan", "sdk", "environment"),
    ),
    LogSignature(
        "msvc.unresolved-symbol", "cpp", "MSVC linker has unresolved external symbols", "high",
        (r"error LNK2001", r"error LNK2019", r"fatal error LNK1120"),
        ("A required library/object is not linked.", "ABI/configuration changed between compiled objects and libraries."),
        "Check target link libraries, architecture/configuration (Debug/Release), runtime settings, and rebuild dependent native libraries.",
        ("msbuild", "cl", "visual studio", "architecture", "project"),
    ),
    LogSignature(
        "msvc.runtime-mismatch", "cpp", "MSVC runtime/ABI mismatch", "critical",
        (r"error LNK2038", r"mismatch detected for ['\"]?_ITERATOR_DEBUG_LEVEL", r"mismatch detected for ['\"]?RuntimeLibrary"),
        ("Objects/libraries were built with incompatible MSVC runtime or debug settings.",),
        "Rebuild all native dependencies with matching architecture, toolset, runtime library, and Debug/Release configuration.",
        ("msvc", "visual studio", "cl", "msbuild", "project"),
    ),
    LogSignature(
        "cpp.compile", "cpp", "C/C++ source compilation failed", "high",
        (r"(?m)^[^\n]+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx):\d+:\d+:\s+(?:fatal\s+)?error:",),
        ("A changed C or C++ source file does not compile under the active compiler.",),
        "Inspect the first compiler diagnostic at the reported source location, correct the source error, then rerun the targeted native build.",
        ("cpp", "source", "compiler", "project"),
    ),
    LogSignature(
        "native.undefined-reference", "cpp", "Native linker has undefined references", "high",
        (r"undefined reference to [`'\"]", r"ld: symbol\(s\) not found", r"collect2: error: ld returned"),
        ("A library/object is omitted or link order is incorrect.", "A dependency ABI changed after a compiler/toolchain update."),
        "Inspect linker inputs/order and rebuild native dependencies using the same compiler, architecture, and standard-library ABI.",
        ("gcc", "clang", "compiler", "architecture", "project"),
    ),
    LogSignature(
        "native.architecture", "cpp", "Binary architecture mismatch", "critical",
        (r"machine type .* conflicts with target machine type", r"file format not recognized", r"wrong ELF class", r"bad CPU type in executable"),
        ("A binary/library was built for a different CPU architecture or target platform.",),
        "Remove stale artifacts and rebuild every native dependency for the active target architecture.",
        ("architecture", "machine", "compiler", "project"),
    ),
    LogSignature(
        "unreal.engine-version", "unreal", "Unreal modules/plugins were built for another engine version", "critical",
        (r"modules are missing or built with a different engine version", r"The following modules are missing or built with a different engine version", r"designed for build .* Attempt to load it anyway"),
        ("The project switched Unreal Engine versions without rebuilding native modules/plugins.",),
        "Use the intended EngineAssociation, regenerate project files, delete stale Binaries/Intermediate only when safe, and rebuild all native modules/plugins.",
        ("unreal", "engine", "uproject", "visual studio", "compiler"),
    ),
    LogSignature(
        "unreal.build-tool", "unreal", "UnrealBuildTool/toolchain failure", "high",
        (r"UnrealBuildTool.*ERROR", r"Unable to find valid installation of Visual Studio", r"Microsoft platform targets must be compiled with Visual Studio"),
        ("Required Visual Studio/C++ workload or Windows SDK is missing/incompatible.",),
        "Verify the Unreal-supported Visual Studio toolset and Windows SDK, then regenerate project files and rebuild.",
        ("unreal", "visual studio", "windows sdk", "msbuild", "cl"),
    ),
    LogSignature(
        "cuda.driver-toolkit", "cuda", "CUDA driver/toolkit compatibility failure", "critical",
        (r"CUDA driver version is insufficient for CUDA runtime version", r"cudaErrorInsufficientDriver", r"no kernel image is available for execution"),
        ("The installed GPU driver does not support the selected CUDA runtime/toolkit or target architecture.",),
        "Align NVIDIA driver, CUDA toolkit/runtime, and GPU compute capability; rebuild CUDA artifacts afterward.",
        ("cuda", "nvcc", "gpu", "driver", "CUDA_PATH"),
    ),
    LogSignature(
        "cuda.compiler", "cuda", "CUDA compilation failed due to host/toolkit mismatch", "high",
        (r"nvcc fatal", r"unsupported GNU version", r"unsupported Microsoft Visual Studio version"),
        ("nvcc is paired with an unsupported host compiler or toolkit configuration.",),
        "Select a CUDA-supported host compiler/toolset or install the toolkit version expected by the project.",
        ("cuda", "nvcc", "gcc", "cl", "visual studio", "compiler"),
    ),
    LogSignature(
        "vulkan.driver", "vulkan", "Vulkan loader/driver initialization failed", "critical",
        (r"VK_ERROR_INCOMPATIBLE_DRIVER", r"failed to find vkGetInstanceProcAddr", r"Cannot find a compatible Vulkan installable client driver"),
        ("The Vulkan loader cannot find a compatible GPU driver/ICD.",),
        "Verify the graphics driver, Vulkan runtime/ICD registration, and VULKAN_SDK; distinguish runtime-driver issues from SDK issues.",
        ("vulkan", "gpu", "driver", "VULKAN_SDK"),
    ),
    LogSignature(
        "gradle.java", "android", "Gradle/JDK compatibility failure", "high",
        (r"Unsupported class file major version", r"Could not determine java version", r"invalid source release", r"requires Java \d+"),
        ("The active JDK is incompatible with Gradle, Android Gradle Plugin, or source-target settings.",),
        "Select the JDK version required by the project's Gradle/Android toolchain and verify JAVA_HOME.",
        ("java", "JAVA_HOME", "gradle", "android"),
    ),
    LogSignature(
        "dotnet.sdk", "dotnet", ".NET SDK mismatch or missing SDK", "high",
        (r"A compatible installed \.NET SDK for global\.json version .* was not found", r"NETSDK1045", r"The specified SDK .* could not be found"),
        ("The SDK pinned by global.json/project settings is not installed or the active SDK is too old.",),
        "Install/select the expected .NET SDK or deliberately update global.json and validate the migration.",
        ("dotnet", "global.json", "sdk"),
    ),
    LogSignature(
        "rust.link", "rust", "Rust link step failed", "high",
        (r"error: linking with .* failed", r"linker .* not found", r"could not compile .* due to .* previous error"),
        ("The native linker/toolchain required by Rust is missing or incompatible.", "A native dependency failed after toolchain drift."),
        "Verify rustup target/toolchain plus the platform linker/C compiler, then rebuild native crates from a clean target directory if needed.",
        ("rust", "rustc", "cargo", "linker", "compiler"),
    ),
    LogSignature(
        "go.module", "go", "Go module dependency state is incomplete", "medium",
        (r"missing go\.sum entry", r"cannot find module providing package", r"go: updates to go\.mod needed"),
        ("go.mod/go.sum and the resolved module graph are out of sync.",),
        "Restore committed go.mod/go.sum or deliberately run the appropriate module tidy/download workflow and review the diff.",
        ("go", "go.mod", "go.sum"),
    ),
    LogSignature(
        "go.syntax", "go", "Go source syntax is invalid", "high",
        (r"(?m)^\.?/?[^\n]+\.go:\d+:\d+:\s+syntax error:",),
        ("A changed Go source file cannot be parsed or compiled.",),
        "Inspect the first reported .go file/line, correct the syntax error, then rerun go test ./....",
        ("go", "source", "project"),
    ),
    LogSignature(
        "docker.daemon", "docker", "Docker daemon is unavailable", "high",
        (r"Cannot connect to the Docker daemon", r"error during connect:.*docker", r"The system cannot find the file specified.*docker_engine"),
        ("Docker Desktop/daemon is stopped or the active Docker context/socket is wrong.",),
        "Start/repair Docker and verify the selected context/socket before rebuilding containers.",
        ("docker", "environment"),
    ),
    LogSignature(
        "resource.disk", "system", "Build failed because storage is exhausted", "critical",
        (r"No space left on device", r"There is not enough space on the disk", r"disk quota exceeded"),
        ("The build/cache/temp volume is full.",),
        "Free space on the build/temp/cache volume, then retry; avoid deleting unique artifacts before confirming they are reproducible.",
        ("host",),
    ),
    LogSignature(
        "resource.memory", "system", "Build/runtime exhausted memory", "critical",
        (r"std::bad_alloc", r"out of memory", r"OutOfMemoryError", r"cannot allocate memory", r"Killed process .* out of memory"),
        ("The process exceeded available RAM/virtual memory or a configured memory limit.",),
        "Reduce parallelism/memory pressure, increase available memory/swap where appropriate, and inspect for runaway allocation if usage is unexpected.",
        ("ram", "host"),
    ),
    LogSignature(
        "system.permission", "system", "Filesystem permission/access failure", "high",
        (r"Permission denied", r"Access is denied", r"UnauthorizedAccessException", r"EACCES"),
        ("The process cannot read/write a required path or another process has restrictive ownership/ACLs.",),
        "Verify path ownership/ACLs and whether a file is locked; avoid broad administrator/root workarounds unless the build genuinely requires elevation.",
        ("path", "environment"),
    ),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run(cmd: Sequence[str], cwd: Optional[Path] = None, timeout: int = 5) -> Optional[str]:
    try:
        p = subprocess.run(
            list(cmd), cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = ((p.stdout or "") + ("\n" + p.stderr if p.stderr else "")).strip()
        return out if out else None
    except Exception:
        return None


def first_line(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    lines = [x.strip() for x in value.splitlines() if x.strip()]
    return lines[0] if lines else None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def version_tuple(text: Optional[str]) -> Tuple[int, ...]:
    if not text:
        return ()
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not m:
        return ()
    return tuple(int(x) for x in m.groups(default="0"))


def state_path(root: Path, filename: str) -> Path:
    return root / STATE_DIR / filename


def ensure_state(root: Path) -> None:
    (root / STATE_DIR).mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def append_jsonl(path: Path, data: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data, separators=(",", ":")) + "\n")


def read_jsonl(path: Path) -> List[dict]:
    if not path.exists():
        return []
    rows: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def get_config(root: Path) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    path = state_path(root, CONFIG_FILE)
    if path.exists():
        try:
            user = load_json(path)
            if isinstance(user, dict):
                cfg.update(user)
        except Exception:
            pass
    return cfg


def get_ram_bytes() -> Optional[int]:
    try:
        if sys.platform.startswith("linux"):
            text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"MemTotal:\s+(\d+)\s+kB", text)
            return int(m.group(1)) * 1024 if m else None
        if sys.platform == "darwin":
            out = run(["sysctl", "-n", "hw.memsize"])
            return int(out) if out and out.isdigit() else None
        if os.name == "nt":
            out = run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"], timeout=7)
            if out:
                return int(out.splitlines()[-1].strip())
    except Exception:
        pass
    return None


def get_gpu() -> Optional[str]:
    try:
        if os.name == "nt":
            out = run(["powershell", "-NoProfile", "-Command",
                       "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"], timeout=7)
            return "; ".join(x.strip() for x in out.splitlines() if x.strip()) if out else None
        if sys.platform.startswith("linux"):
            out = run(["lspci"])
            if out:
                hits = [x for x in out.splitlines() if "vga" in x.lower() or "3d controller" in x.lower()]
                return "; ".join(hits[:3]) or None
        if sys.platform == "darwin":
            out = run(["system_profiler", "SPDisplaysDataType"], timeout=8)
            if out:
                chips = [x.split(":", 1)[1].strip() for x in out.splitlines() if "Chipset Model:" in x]
                return "; ".join(chips) or None
    except Exception:
        pass
    return None


def windows_visual_studio() -> dict:
    if os.name != "nt":
        return {"present": False}
    candidates = []
    for env_name in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(env_name)
        if base:
            candidates.append(Path(base) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe")
    for exe in candidates:
        if exe.exists():
            path = first_line(run([str(exe), "-latest", "-products", "*",
                                   "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                   "-property", "installationPath"], timeout=7))
            if path:
                ver = first_line(run([str(exe), "-latest", "-products", "*", "-property", "catalog_productDisplayVersion"], timeout=7))
                return {"present": True, "path": path, "version": ver, "source": "vswhere"}
    return {"present": False}


def discover_project_files(root: Path, max_depth: int = 5) -> Dict[str, dict]:
    files: Dict[str, dict] = {}
    for base, dirs, names in os.walk(root):
        base_path = Path(base)
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        try:
            depth = len(base_path.relative_to(root).parts)
        except ValueError:
            depth = 0
        if depth > max_depth:
            dirs[:] = []
            continue
        for name in names:
            suffix = Path(name).suffix.lower()
            if name not in TRACKED_FILES and suffix not in TRACKED_SUFFIXES:
                continue
            p = base_path / name
            rel = str(p.relative_to(root)).replace("\\", "/")
            try:
                stat = p.stat()
                rec = {"sha256": sha256_file(p), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
                if suffix == ".uproject":
                    try:
                        data = json.loads(p.read_text(encoding="utf-8"))
                        rec["engine_association"] = data.get("EngineAssociation")
                        rec["plugins"] = sorted(x.get("Name") for x in data.get("Plugins", []) if x.get("Enabled") and x.get("Name"))
                    except Exception:
                        rec["engine_association"] = None
                files[rel] = rec
            except OSError:
                pass
    return files


def scan_source_shape(root: Path, max_depth: int = 5, max_files: int = 25000) -> dict:
    counts: Dict[str, int] = {}
    total = 0
    flags = {"cuda": False, "vulkan": False, "hlsl": False, "firmware": False}
    for base, dirs, names in os.walk(root):
        base_path = Path(base)
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        try:
            depth = len(base_path.relative_to(root).parts)
        except ValueError:
            depth = 0
        if depth > max_depth:
            dirs[:] = []
            continue
        for name in names:
            total += 1
            if total > max_files:
                return {"counts": counts, "total_seen": total, "truncated": True, "flags": flags}
            suffix = Path(name).suffix.lower()
            if suffix:
                counts[suffix] = counts.get(suffix, 0) + 1
            if suffix == ".cu": flags["cuda"] = True
            if suffix in {".vert", ".frag", ".spv", ".glsl"}: flags["vulkan"] = True
            if suffix in {".hlsl", ".fx"}: flags["hlsl"] = True
            if suffix in {".ino", ".hex", ".elf"}: flags["firmware"] = True
    return {"counts": counts, "total_seen": total, "truncated": False, "flags": flags}


def infer_project(root: Path, project_files: Dict[str, dict], source_shape: dict) -> dict:
    names = {Path(p).name for p in project_files}
    suffixes = {Path(p).suffix.lower() for p in project_files}
    src = source_shape.get("counts", {})
    families: List[str] = []
    reasons: Dict[str, str] = {}

    def mark(family: str, reason: str):
        if family not in families:
            families.append(family)
            reasons[family] = reason

    if any(x in names for x in {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"}) or src.get(".py", 0):
        mark("python", "Python source or packaging manifest detected")
    if any(x in names for x in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}):
        mark("node", "Node package manifest detected")
    if "Cargo.toml" in names or src.get(".rs", 0): mark("rust", "Rust source or Cargo manifest detected")
    if "go.mod" in names or src.get(".go", 0): mark("go", "Go source/module detected")
    if "CMakeLists.txt" in names or src.get(".cpp", 0) or src.get(".cc", 0) or src.get(".cxx", 0):
        mark("cpp", "C/C++ source or CMake configuration detected")
    if ".sln" in suffixes or ".csproj" in suffixes or src.get(".cs", 0): mark("dotnet", ".NET project/source detected")
    if ".uproject" in suffixes: mark("unreal", "Unreal .uproject detected")
    if (root / "Assets").is_dir() and (root / "ProjectSettings").is_dir(): mark("unity", "Unity project layout detected")
    if any(x in names for x in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}) and ((root / "app").exists() or os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")):
        mark("android", "Gradle + Android indicators detected")
    if "Dockerfile" in names or "docker-compose.yml" in names or "docker-compose.yaml" in names: mark("docker", "Docker configuration detected")
    if source_shape.get("flags", {}).get("cuda") or os.environ.get("CUDA_PATH"): mark("cuda", "CUDA source/SDK indicator detected")
    if source_shape.get("flags", {}).get("vulkan") or os.environ.get("VULKAN_SDK"): mark("vulkan", "Vulkan shader/SDK indicator detected")
    if source_shape.get("flags", {}).get("firmware"): mark("firmware", "Firmware artifact/source indicator detected")

    return {"families": families, "reasons": reasons, "source_shape": source_shape}


def get_git_state(root: Path) -> dict:
    if not (root / ".git").exists():
        return {"is_repo": False}
    return {
        "is_repo": True,
        "branch": first_line(run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)),
        "commit": first_line(run(["git", "rev-parse", "HEAD"], cwd=root)),
        "dirty": bool(run(["git", "status", "--porcelain"], cwd=root)),
    }


def collect_snapshot(root: Path) -> dict:
    cfg = get_config(root)
    tools = {}
    for name, cmd in TOOL_COMMANDS.items():
        out = run(cmd)
        exe = cmd[0]
        tools[name] = {
            "present": out is not None,
            "version": first_line(out),
            "path": shutil.which(exe) if exe != sys.executable else sys.executable,
        }
    vs = windows_visual_studio()
    env = {key: os.environ.get(key) for key in IMPORTANT_ENV if os.environ.get(key)}
    files = discover_project_files(root, int(cfg.get("max_scan_depth", 5)))
    shape = scan_source_shape(root, int(cfg.get("max_scan_depth", 5)), int(cfg.get("max_source_files", 25000)))
    project = infer_project(root, files, shape)
    return {
        "schema": 2,
        "app_version": APP_VERSION,
        "timestamp": now_iso(),
        "project_root": str(root.resolve()),
        "host": {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_implementation": platform.python_implementation(),
            "ram_bytes": get_ram_bytes(),
            "gpu": get_gpu(),
        },
        "tools": tools,
        "visual_studio_cpp": vs,
        "environment": env,
        "project_files": files,
        "project": project,
        "git": get_git_state(root),
    }


def add(findings: List[Finding], severity: str, category: str, item: str,
        baseline, current, message: str, recommendation: str) -> None:
    findings.append(Finding(
        severity, category, item,
        str(baseline if baseline is not None else "missing"),
        str(current if current is not None else "missing"),
        message, recommendation,
    ))


def compare_versions(name: str, old: Optional[str], new: Optional[str], findings: List[Finding]) -> None:
    ov, nv = version_tuple(old), version_tuple(new)
    if not ov or not nv or ov == nv:
        return
    if ov[0] != nv[0]:
        add(findings, "high", "toolchain", name, old, new,
            f"{name} major version changed.",
            f"Validate the project with {name} {new}; pin or restore the prior major version if failures appear.")
    elif len(ov) > 1 and len(nv) > 1 and ov[1] != nv[1]:
        sev = "high" if name in {"python", "java", "dotnet", "cmake", "nvcc"} else "medium"
        add(findings, sev, "toolchain", name, old, new,
            f"{name} minor version changed.", "Run the project's tests/build before accepting the new environment.")
    elif ov[:3] != nv[:3]:
        add(findings, "low", "toolchain", name, old, new,
            f"{name} patch version changed.", "Usually low risk, but verify reproducible builds and regression tests.")


def compare(baseline: dict, current: dict) -> List[Finding]:
    findings: List[Finding] = []
    bh, ch = baseline.get("host", {}), current.get("host", {})
    if bh.get("os") != ch.get("os"):
        add(findings, "critical", "host", "operating system", bh.get("os"), ch.get("os"),
            "Project moved to a different operating-system family.",
            "Rebuild native dependencies and validate platform-specific code/configuration.")
    if bh.get("machine") != ch.get("machine"):
        add(findings, "critical", "host", "architecture", bh.get("machine"), ch.get("machine"),
            "CPU architecture changed.", "Rebuild native artifacts and verify architecture-specific dependencies.")
    if bh.get("gpu") and ch.get("gpu") and bh.get("gpu") != ch.get("gpu"):
        add(findings, "medium", "hardware", "GPU", bh.get("gpu"), ch.get("gpu"),
            "Graphics hardware identity changed.", "Revalidate graphics/compute workloads, shaders, drivers, and VRAM assumptions.")

    btools, ctools = baseline.get("tools", {}), current.get("tools", {})
    for name in sorted(set(btools) | set(ctools)):
        b, c = btools.get(name, {}), ctools.get(name, {})
        if b.get("present") and not c.get("present"):
            add(findings, "high", "toolchain", name, b.get("version"), None,
                f"Previously-present tool '{name}' disappeared.", f"Restore {name} or update the project so it no longer depends on it.")
        elif not b.get("present") and c.get("present"):
            add(findings, "info", "toolchain", name, None, c.get("version"),
                f"New tool '{name}' is now installed.", "No action required unless build selection changed.")
        elif b.get("present") and c.get("present"):
            compare_versions(name, b.get("version"), c.get("version"), findings)
            if b.get("path") and c.get("path") and b.get("path") != c.get("path"):
                add(findings, "medium", "toolchain", name + " path", b.get("path"), c.get("path"),
                    f"{name} resolves to a different executable.", "Confirm PATH/toolchain selection is intentional.")

    bvs, cvs = baseline.get("visual_studio_cpp", {}), current.get("visual_studio_cpp", {})
    if bvs.get("present") and not cvs.get("present"):
        add(findings, "high", "toolchain", "Visual Studio C++ workload", bvs.get("version"), None,
            "Visual Studio C++ workload is no longer discoverable.", "Repair/install the C++ workload or select another supported compiler.")
    elif bvs.get("present") and cvs.get("present") and bvs.get("path") != cvs.get("path"):
        add(findings, "medium", "toolchain", "Visual Studio installation", bvs.get("path"), cvs.get("path"),
            "A different Visual Studio installation is selected.", "Regenerate native project files and validate ABI/toolset compatibility.")

    benv, cenv = baseline.get("environment", {}), current.get("environment", {})
    for key in sorted(set(benv) | set(cenv)):
        if benv.get(key) != cenv.get(key):
            add(findings, "medium", "environment", key, benv.get(key), cenv.get(key),
                f"Build-related environment variable {key} changed.", "Check whether this redirects the SDK, compiler, or package manager.")

    bfiles, cfiles = baseline.get("project_files", {}), current.get("project_files", {})
    for path in sorted(set(bfiles) | set(cfiles)):
        b, c = bfiles.get(path), cfiles.get(path)
        if b and not c:
            add(findings, "high", "project", path, b.get("sha256", "")[:12], None,
                "Tracked build/dependency file was removed.", "Confirm the deletion and replacement configuration are intentional.")
        elif not b and c:
            add(findings, "medium", "project", path, None, c.get("sha256", "")[:12],
                "New build/dependency file appeared.", "Review it for a new package manager, build path, or source of version truth.")
        elif b and c and b.get("sha256") != c.get("sha256"):
            name = Path(path).name.lower()
            lockish = "lock" in name or name.endswith(".sum")
            sev = "high" if lockish else "medium"
            add(findings, sev, "project", path, b.get("sha256", "")[:12], c.get("sha256", "")[:12],
                "Dependency/build manifest changed.", "Re-resolve dependencies if needed and run the project's build/test suite.")
        if b and c and path.endswith(".uproject") and b.get("engine_association") != c.get("engine_association"):
            add(findings, "high", "engine", path, b.get("engine_association"), c.get("engine_association"),
                "Unreal Engine association changed.", "Use the intended engine, regenerate project files, then rebuild C++ modules/plugins.")

    bp = set(baseline.get("project", {}).get("families", []))
    cp = set(current.get("project", {}).get("families", []))
    for family in sorted(cp - bp):
        add(findings, "medium", "project-shape", family, "absent", "present",
            f"Project acquired a new {family} technology surface.", "Validate the newly introduced SDK/toolchain and add it to build/release checks.")

    bgit, cgit = baseline.get("git", {}), current.get("git", {})
    if bgit.get("is_repo") and cgit.get("is_repo") and bgit.get("branch") != cgit.get("branch"):
        add(findings, "info", "git", "branch", bgit.get("branch"), cgit.get("branch"),
            "Git branch changed since the baseline.", "Informational: use branch-specific baselines if environments intentionally differ.")
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.item))


def stability_score(findings: List[Finding]) -> int:
    return max(0, 100 - sum(DEDUCTIONS[f.severity] for f in findings))


def stability_status(score_value: int, findings: List[Finding]) -> str:
    if any(f.severity == "critical" for f in findings): return "CRITICAL"
    if score_value < 60: return "UNSTABLE"
    if score_value < 85: return "DRIFTING"
    return "STABLE"


def tool_present(snapshot: dict, name: str) -> bool:
    return bool(snapshot.get("tools", {}).get(name, {}).get("present"))


def doctor(snapshot: dict) -> List[Requirement]:
    families = set(snapshot.get("project", {}).get("families", []))
    reqs: List[Requirement] = []

    def require_tool(family: str, tool: str, rec: str, severity: str = "high"):
        if family not in families:
            return
        t = snapshot.get("tools", {}).get(tool, {})
        ok = bool(t.get("present"))
        reqs.append(Requirement(
            f"{family}:{tool}", "ok" if ok else "missing",
            t.get("version") or t.get("path") or "not found",
            "No action required." if ok else rec,
            severity,
        ))

    require_tool("python", "python", "Install/select the Python interpreter used by this project.")
    require_tool("node", "node", "Install the project's expected Node.js version.")
    require_tool("node", "npm", "Install/repair npm or use the package manager declared by the project.", "medium")
    require_tool("rust", "rustc", "Install the Rust toolchain with rustup.")
    require_tool("rust", "cargo", "Install/repair Cargo.")
    require_tool("go", "go", "Install the expected Go toolchain.")
    require_tool("dotnet", "dotnet", "Install the expected .NET SDK.")
    require_tool("android", "java", "Install/select the JDK required by the Android/Gradle toolchain.")
    require_tool("android", "adb", "Install Android platform-tools and ensure adb is on PATH.", "medium")
    require_tool("cuda", "nvcc", "Install/select the CUDA Toolkit and verify CUDA_PATH.")
    require_tool("docker", "docker", "Install/start Docker if container builds are part of this project.", "medium")

    if "cpp" in families:
        cmake_needed = "CMakeLists.txt" in {Path(p).name for p in snapshot.get("project_files", {})}
        if cmake_needed:
            require_tool("cpp", "cmake", "Install/select the CMake version expected by the project.")
        compiler_ok = any(tool_present(snapshot, x) for x in ("cl", "gcc", "clang")) or snapshot.get("visual_studio_cpp", {}).get("present")
        evidence = []
        for x in ("cl", "gcc", "clang"):
            if tool_present(snapshot, x): evidence.append(x)
        if snapshot.get("visual_studio_cpp", {}).get("present"): evidence.append("Visual Studio C++ workload")
        reqs.append(Requirement(
            "cpp:compiler", "ok" if compiler_ok else "missing",
            ", ".join(evidence) if evidence else "no supported compiler discovered",
            "No action required." if compiler_ok else "Install/select MSVC, GCC, or Clang; then regenerate native build files.",
            "high",
        ))

    if "vulkan" in families:
        env_ok = bool(snapshot.get("environment", {}).get("VULKAN_SDK"))
        tool_ok = tool_present(snapshot, "vulkaninfo")
        ok = env_ok or tool_ok
        reqs.append(Requirement(
            "vulkan:sdk", "ok" if ok else "missing",
            snapshot.get("environment", {}).get("VULKAN_SDK") or ("vulkaninfo available" if tool_ok else "not detected"),
            "No action required." if ok else "Install/select the Vulkan SDK and verify VULKAN_SDK.",
            "high",
        ))

    if "unreal" in families:
        associations = [r.get("engine_association") for p, r in snapshot.get("project_files", {}).items() if p.endswith(".uproject")]
        assoc_ok = any(x for x in associations)
        reqs.append(Requirement(
            "unreal:engine-association", "ok" if assoc_ok else "warning",
            ", ".join(str(x) for x in associations if x) or "not declared",
            "EngineAssociation is not always required, but a pinned association reduces accidental engine switching.",
            "medium",
        ))

    return reqs


def finding_key(f: dict) -> str:
    return f"{f.get('category')}::{f.get('item')}::{f.get('severity')}"


def _clip(text: str, limit: int = 220) -> str:
    clean = " ".join(str(text).strip().split())
    return clean if len(clean) <= limit else clean[:limit - 1] + "…"


def correlate_drift(signature: LogSignature, report: Optional[dict]) -> List[dict]:
    if not report:
        return []
    terms = {x.lower() for x in signature.drift_terms}
    terms.add(signature.ecosystem.lower())
    correlated: List[dict] = []
    seen_items = set()
    for f in report.get("findings", []):
        hay = " ".join(str(f.get(k, "")) for k in ("category", "item", "baseline", "current", "message")).lower()
        matched = sorted(t for t in terms if t and t in hay)
        item = str(f.get("item"))
        if matched and item not in seen_items:
            seen_items.add(item)
            correlated.append({
                "severity": f.get("severity"),
                "item": f.get("item"),
                "message": f.get("message"),
                "matched_terms": matched,
            })
    return correlated[:5]


def analyze_log_text(text: str, report: Optional[dict] = None, source: str = "inline") -> dict:
    """Classify a build/runtime log using deterministic, inspectable signatures."""
    text = text or ""
    lines = text.splitlines()
    matches: List[dict] = []
    for signature in LOG_SIGNATURES:
        excerpts: List[str] = []
        hit_count = 0
        compiled = [re.compile(p, re.IGNORECASE) for p in signature.patterns]
        for line in lines:
            if any(rx.search(line) for rx in compiled):
                hit_count += 1
                if len(excerpts) < 3:
                    excerpts.append(_clip(line))
        if not hit_count:
            continue
        correlated = correlate_drift(signature, report)
        sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(signature.severity, 1)
        confidence_score = min(0.99, 0.48 + 0.10 * min(hit_count, 3) + 0.08 * min(len(correlated), 3) + 0.05 * sev_weight)
        matches.append({
            "signature_id": signature.signature_id,
            "ecosystem": signature.ecosystem,
            "title": signature.title,
            "severity": signature.severity,
            "hits": hit_count,
            "confidence": round(confidence_score, 2),
            "excerpts": excerpts,
            "probable_causes": list(signature.causes),
            "recommendation": signature.recommendation,
            "correlated_drift": correlated,
        })

    matches.sort(key=lambda m: (-SEVERITY_ORDER.get(m["severity"], 0), -m["confidence"], -m["hits"], m["signature_id"]))
    primary = matches[0] if matches else None
    return {
        "schema": 1,
        "analyzed_at": now_iso(),
        "source": source,
        "line_count": len(lines),
        "matched_signatures": len(matches),
        "primary": primary,
        "signatures": matches,
        "unclassified": not bool(matches),
        "guidance": (
            "No known failure signature matched. Preserve the full log and inspect the first causal error, not only the final non-zero exit message."
            if not matches else
            "Treat the primary signature as a hypothesis supported by matched log text and correlated drift; confirm it with the recommended validation step."
        ),
    }


def load_recent_incidents(root: Path, limit: int = 20) -> List[dict]:
    rows = read_jsonl(state_path(root, INCIDENTS_FILE))
    return rows[-max(1, limit):]


def save_incident(root: Path, diagnosis: dict, command: Optional[List[str]] = None,
                  exit_code: Optional[int] = None, log_path: Optional[str] = None) -> dict:
    ensure_state(root)
    incident = {
        "timestamp": now_iso(),
        "command": command or [],
        "exit_code": exit_code,
        "log_path": log_path,
        "primary_signature": (diagnosis.get("primary") or {}).get("signature_id"),
        "severity": (diagnosis.get("primary") or {}).get("severity"),
        "ecosystem": (diagnosis.get("primary") or {}).get("ecosystem"),
        "matched_signatures": [x.get("signature_id") for x in diagnosis.get("signatures", [])],
        "diagnosis": diagnosis,
    }
    append_jsonl(state_path(root, INCIDENTS_FILE), incident)
    return incident


def print_diagnosis(diagnosis: dict) -> None:
    print("\nLOG DIAGNOSIS")
    print("-" * 78)
    if diagnosis.get("unclassified"):
        print("No known failure signature matched.")
        print(diagnosis.get("guidance", ""))
        return
    for i, sig in enumerate(diagnosis.get("signatures", [])[:6], 1):
        print(f"{i:02d}. [{sig['severity'].upper():8}] {sig['title']}  ({sig['signature_id']})")
        print(f"    confidence: {sig['confidence']:.0%}  hits={sig['hits']}")
        if sig.get("excerpts"):
            print(f"    evidence  : {sig['excerpts'][0]}")
        if sig.get("probable_causes"):
            print(f"    cause     : {sig['probable_causes'][0]}")
        print(f"    action    : {sig['recommendation']}")
        if sig.get("correlated_drift"):
            print("    drift     : " + "; ".join(str(x.get("item")) for x in sig["correlated_drift"][:3]))


def predict_risk(root: Path, report: dict, requirements: List[Requirement]) -> dict:
    events = read_jsonl(state_path(root, EVENTS_FILE))
    findings = report.get("findings", [])
    drift_component = min(1.0, (100 - report.get("score", 100)) / 70.0)
    missing = [r for r in requirements if r.status == "missing"]
    warnings = [r for r in requirements if r.status == "warning"]
    requirement_component = min(1.0, (len(missing) * 0.45) + (len(warnings) * 0.12))

    failures = sum(1 for e in events if e.get("result") == "failure")
    successes = sum(1 for e in events if e.get("result") == "success")
    n = failures + successes
    prior_failure = (failures + 1) / (n + 2) if n else 0.15

    current_keys = {finding_key(f) for f in findings}
    assoc_values: List[Tuple[float, str]] = []
    for key in sorted(current_keys):
        rel = [e for e in events if key in set(e.get("finding_keys", []))]
        if rel:
            fcount = sum(1 for e in rel if e.get("result") == "failure")
            prob = (fcount + 1) / (len(rel) + 2)
            assoc_values.append((prob, key))
    association_component = max([prob for prob, _ in assoc_values], default=prior_failure)

    recent = [e for e in events[-10:] if e.get("result") in {"success", "failure"}]
    recent_fail_rate = (sum(1 for e in recent if e.get("result") == "failure") / len(recent)) if recent else prior_failure
    history_component = 0.65 * association_component + 0.35 * recent_fail_rate

    # v3: repeated classified failures add a small decaying operational-risk signal.
    recent_failed = [e for e in events[-12:] if e.get("result") == "failure"]
    signature_counts = Counter(
        sig for e in recent_failed for sig in (e.get("failure_signatures") or []) if sig
    )
    sig_events = sum(signature_counts.values())
    signature_component = min(1.0, sig_events / 6.0)
    if recent and recent[-1].get("result") == "success":
        signature_component *= 0.65

    raw = 100 * (
        0.47 * drift_component +
        0.25 * requirement_component +
        0.20 * history_component +
        0.08 * signature_component
    )
    if any(f.get("severity") == "critical" for f in findings):
        raw = max(raw, 82)
    if len(missing) >= 2:
        raw = max(raw, 72)
    risk = max(0, min(100, round(raw)))

    if risk < 20: label = "LOW"
    elif risk < 45: label = "GUARDED"
    elif risk < 70: label = "ELEVATED"
    else: label = "HIGH"

    confidence = "HIGH" if n >= 20 else ("MEDIUM" if n >= 6 else "LOW")
    drivers = []
    for f in findings[:5]:
        if f.get("severity") != "info":
            drivers.append({"type": "drift", "severity": f.get("severity"), "item": f.get("item"), "detail": f.get("message")})
    for r in missing[:4]:
        drivers.append({"type": "requirement", "severity": r.severity, "item": r.capability, "detail": r.recommendation})
    for sig, count in signature_counts.most_common(3):
        drivers.append({
            "type": "failure-signature", "severity": "high", "item": sig,
            "detail": f"Observed {count} time(s) in recent failed guarded commands."
        })
    if n:
        drivers.append({"type": "history", "severity": "info", "item": "recorded-build-history",
                        "detail": f"{failures} failures / {n} recorded outcomes; recent failure rate {recent_fail_rate:.0%}."})

    return {
        "risk": risk,
        "label": label,
        "confidence": confidence,
        "recorded_outcomes": n,
        "historical_failure_rate": round(prior_failure, 4),
        "recent_failure_signatures": dict(signature_counts.most_common(8)),
        "components": {
            "drift": round(drift_component, 4),
            "requirements": round(requirement_component, 4),
            "history": round(history_component, 4),
            "failure_signatures": round(signature_component, 4),
        },
        "drivers": drivers,
    }

def make_report(root: Path) -> dict:
    baseline_path = state_path(root, BASELINE_FILE)
    if not baseline_path.exists():
        raise FileNotFoundError("No baseline. Run: driftguard init")
    baseline = load_json(baseline_path)
    current = collect_snapshot(root)
    findings = compare(baseline, current)
    score_value = stability_score(findings)
    reqs = doctor(current)
    report = {
        "schema": 3,
        "generated_at": now_iso(),
        "project_root": str(root.resolve()),
        "baseline_timestamp": baseline.get("timestamp"),
        "score": score_value,
        "status": stability_status(score_value, findings),
        "counts": {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in findings],
        "requirements": [asdict(r) for r in reqs],
        "current": current,
        "recent_incidents": load_recent_incidents(root, int(get_config(root).get("incident_history_limit", 100)))[-8:],
    }
    report["prediction"] = predict_risk(root, report, reqs)
    ensure_state(root)
    write_json(state_path(root, LAST_REPORT_FILE), report)
    append_jsonl(state_path(root, HISTORY_FILE), {
        "timestamp": report["generated_at"], "score": report["score"], "status": report["status"],
        "risk": report["prediction"]["risk"], "risk_label": report["prediction"]["label"], "counts": report["counts"],
    })
    return report


def record_outcome(root: Path, result: str, stage: str, note: str = "", command: Optional[List[str]] = None,
                   exit_code: Optional[int] = None, diagnosis: Optional[dict] = None,
                   log_path: Optional[str] = None, report: Optional[dict] = None) -> dict:
    # Guard callers should reuse the preflight report so the outcome is associated
    # with the conditions that existed before execution, while avoiding a duplicate
    # full project scan. Direct record callers still collect a fresh report.
    if report is None:
        report = make_report(root)
    failure_signatures = [x.get("signature_id") for x in (diagnosis or {}).get("signatures", []) if x.get("signature_id")]
    event = {
        "timestamp": now_iso(),
        "result": result,
        "stage": stage,
        "note": note,
        "command": command or [],
        "exit_code": exit_code,
        "risk": report["prediction"]["risk"],
        "score": report["score"],
        "finding_keys": [finding_key(f) for f in report["findings"]],
        "project_families": report.get("current", {}).get("project", {}).get("families", []),
        "failure_signatures": failure_signatures,
        "primary_failure_signature": ((diagnosis or {}).get("primary") or {}).get("signature_id"),
        "log_path": log_path,
    }
    append_jsonl(state_path(root, EVENTS_FILE), event)
    return event

def print_report(report: dict) -> None:
    p = report.get("prediction", {})
    print(f"\nDriftGuard {APP_VERSION}")
    print("=" * 78)
    print(f"Stability : {report['status']:<10} {report['score']}/100")
    print(f"Build risk: {p.get('label','?'):<10} {p.get('risk','?')}/100   confidence={p.get('confidence','?')}")
    families = report.get("current", {}).get("project", {}).get("families", [])
    print(f"Project   : {', '.join(families) if families else 'generic/unknown'}")
    print(f"Root      : {report['project_root']}")
    print(f"Baseline  : {report['baseline_timestamp']}")
    print("-" * 78)

    missing = [r for r in report.get("requirements", []) if r.get("status") != "ok"]
    if missing:
        print("PROJECT REQUIREMENTS")
        for r in missing:
            print(f"  [{r['status'].upper():7}] {r['capability']}: {r['evidence']}")
            print(f"             {r['recommendation']}")
        print("-" * 78)

    findings = report["findings"]
    if not findings:
        print("No baseline drift detected.")
    else:
        for i, f in enumerate(findings, 1):
            print(f"{i:02d}. [{f['severity'].upper():8}] {f['category']} :: {f['item']}")
            print(f"    {f['message']}")
            print(f"    baseline: {f['baseline']}")
            print(f"    current : {f['current']}")
            print(f"    action  : {f['recommendation']}")


def sparkline(history: List[dict], key: str, width: int = 520, height: int = 90) -> str:
    vals = [float(x.get(key, 0)) for x in history[-30:] if isinstance(x.get(key), (int, float))]
    if len(vals) < 2:
        return "<div class='muted'>Not enough history yet.</div>"
    pts = []
    for i, val in enumerate(vals):
        x = 8 + i * (width - 16) / (len(vals) - 1)
        y = 8 + (100 - val) * (height - 16) / 100
        pts.append(f"{x:.1f},{y:.1f}")
    return f"<svg viewBox='0 0 {width} {height}' role='img'><polyline points='{' '.join(pts)}' fill='none' stroke='currentColor' stroke-width='3'/></svg>"


def report_html(root: Path, report: dict) -> str:
    findings = report.get("findings", [])
    rows = []
    for f in findings:
        rows.append("<tr>" +
            f"<td><span class='sev {html.escape(f['severity'])}'>{html.escape(f['severity'].upper())}</span></td>" +
            f"<td>{html.escape(f['category'])}</td><td>{html.escape(f['item'])}</td>" +
            f"<td>{html.escape(f['message'])}</td><td><code>{html.escape(f['baseline'])}</code></td>" +
            f"<td><code>{html.escape(f['current'])}</code></td><td>{html.escape(f['recommendation'])}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan='7' class='ok'>No baseline drift detected.</td></tr>")

    req_rows = []
    for r in report.get("requirements", []):
        req_rows.append(f"<tr><td>{html.escape(r['capability'])}</td><td class='{html.escape(r['status'])}'>{html.escape(r['status'].upper())}</td>"
                        f"<td>{html.escape(r['evidence'])}</td><td>{html.escape(r['recommendation'])}</td></tr>")
    if not req_rows:
        req_rows.append("<tr><td colspan='4' class='muted'>No project-specific requirements inferred.</td></tr>")

    history = read_jsonl(state_path(root, HISTORY_FILE))
    p = report.get("prediction", {})
    families = report.get("current", {}).get("project", {}).get("families", [])
    drivers = "".join(f"<li><b>{html.escape(str(x.get('item','')))}</b> — {html.escape(str(x.get('detail','')))}</li>" for x in p.get("drivers", []))
    if not drivers: drivers = "<li>No material risk drivers.</li>"

    subsystem_rows = []
    for sub in p.get("subsystem_prediction", {}).get("subsystems", []):
        ev = "; ".join(str(x) for x in sub.get("evidence", [])[:3]) or "No material evidence."
        subsystem_rows.append(
            f"<tr><td>{html.escape(str(sub.get('subsystem','')))}</td>"
            f"<td>{sub.get('risk',0)}/100</td><td>{html.escape(str(sub.get('label','')))}</td>"
            f"<td>{html.escape(ev)}</td><td><code>{html.escape(str(sub.get('validation') or 'targeted project check'))}</code></td></tr>"
        )
    if not subsystem_rows:
        subsystem_rows.append("<tr><td colspan='5' class='muted'>Subsystem prediction is not available yet.</td></tr>")

    incident_rows = []
    for incident in reversed(report.get("recent_incidents", [])[-8:]):
        diag = incident.get("diagnosis") or {}
        primary = diag.get("primary") or {}
        incident_rows.append(
            f"<tr><td>{html.escape(str(incident.get('timestamp','')))}</td>"
            f"<td class='{html.escape(str(incident.get('severity') or 'info'))}'>{html.escape(str(incident.get('severity') or 'unknown').upper())}</td>"
            f"<td>{html.escape(str(incident.get('primary_signature') or 'unclassified'))}</td>"
            f"<td>{html.escape(str(primary.get('title') or 'No classified signature'))}</td>"
            f"<td>{html.escape(str(primary.get('recommendation') or diag.get('guidance') or ''))}</td></tr>"
        )
    if not incident_rows:
        incident_rows.append("<tr><td colspan='5' class='muted'>No classified build incidents recorded yet.</td></tr>")

    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<meta http-equiv='refresh' content='10'><title>DriftGuard 4</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--panel2:#1c2128;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--green:#3fb950;--yellow:#d29922;--orange:#db6d28;--red:#f85149}}
*{{box-sizing:border-box}} body{{margin:0;padding:28px;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}} h1,h2{{margin:0 0 10px}} h2{{margin-top:26px}}
header{{display:flex;gap:18px;align-items:center;flex-wrap:wrap}} .dial{{width:108px;height:108px;border-radius:18px;display:grid;place-items:center;background:var(--panel);border:1px solid var(--line)}} .dial b{{font-size:31px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:20px 0}} .card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}} .card b{{display:block;font-size:22px;margin-top:4px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}} .panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}} .muted{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}} th,td{{border-bottom:1px solid var(--line);text-align:left;vertical-align:top;padding:9px}} th{{background:var(--panel2)}} code{{color:#c9d1d9;word-break:break-all}}
.critical,.high,.missing{{color:var(--red)}} .medium,.warning{{color:var(--orange)}} .low{{color:var(--yellow)}} .info,.ok{{color:var(--green)}} svg{{width:100%;max-height:100px;color:#58a6ff}} li{{margin:6px 0}}
</style></head><body>
<header><div class='dial'><div><b>{p.get('risk',0)}</b><br>risk / 100</div></div><div><h1>DriftGuard 4 — {html.escape(p.get('label','UNKNOWN'))} build risk</h1><div class='muted'>Stability {report.get('score',0)}/100 · {html.escape(report.get('status',''))}</div><div class='muted'>{html.escape(report.get('project_root',''))}</div><div class='muted'>Project: {html.escape(', '.join(families) if families else 'generic/unknown')}</div></div></header>
<div class='cards'><div class='card'>Prediction confidence<b>{html.escape(p.get('confidence','?'))}</b></div><div class='card'>Recorded outcomes<b>{p.get('recorded_outcomes',0)}</b></div><div class='card'>Critical drift<b>{report.get('counts',{}).get('critical',0)}</b></div><div class='card'>High drift<b>{report.get('counts',{}).get('high',0)}</b></div></div>
<div class='grid'><div class='panel'><h2>Risk drivers</h2><ul>{drivers}</ul></div><div class='panel'><h2>Risk trend</h2>{sparkline(history,'risk')}</div><div class='panel'><h2>Stability trend</h2>{sparkline(history,'score')}</div></div>
<h2>Subsystem failure prediction</h2><table><thead><tr><th>Subsystem</th><th>Risk</th><th>Level</th><th>Evidence</th><th>Validate first</th></tr></thead><tbody>{''.join(subsystem_rows)}</tbody></table>
<h2>Recent classified incidents</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Signature</th><th>Diagnosis</th><th>Recommended action</th></tr></thead><tbody>{''.join(incident_rows)}</tbody></table>
<h2>Project requirements</h2><table><thead><tr><th>Capability</th><th>Status</th><th>Evidence</th><th>Action</th></tr></thead><tbody>{''.join(req_rows)}</tbody></table>
<h2>Environment drift</h2><table><thead><tr><th>Severity</th><th>Area</th><th>Item</th><th>Finding</th><th>Baseline</th><th>Current</th><th>Action</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<p class='muted'>Auto-refreshes every 10 seconds. Risk prediction becomes more project-specific as successful and failed build/test outcomes are recorded.</p></body></html>"""


def cmd_init(root: Path, force: bool) -> int:
    ensure_state(root)
    path = state_path(root, BASELINE_FILE)
    if path.exists() and not force:
        print(f"Baseline already exists: {path}\nUse --force to replace it.")
        return 2
    snapshot = collect_snapshot(root)
    write_json(path, snapshot)
    cfg_path = state_path(root, CONFIG_FILE)
    if not cfg_path.exists():
        write_json(cfg_path, DEFAULT_CONFIG)
    print(f"Baseline created: {path}")
    print(f"Project families: {', '.join(snapshot['project']['families']) or 'generic/unknown'}")
    print(f"Tracked {len(snapshot['project_files'])} configuration/build file(s).")
    return 0


def cmd_check(root: Path, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr); return 2
    print(json.dumps(report, indent=2) if json_output else "", end="" if json_output else "")
    if not json_output: print_report(report)
    return 1 if report["status"] in {"CRITICAL", "UNSTABLE"} else 0


def cmd_predict(root: Path, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr); return 2
    p = report["prediction"]
    if json_output:
        print(json.dumps(p, indent=2))
    else:
        print(f"Predicted build-failure risk: {p['risk']}/100 ({p['label']}) — confidence {p['confidence']}")
        print(f"Recorded outcomes: {p['recorded_outcomes']}")
        if p["drivers"]:
            print("Drivers:")
            for d in p["drivers"]:
                print(f"  - {d['item']}: {d['detail']}")
    return 1 if p["risk"] >= get_config(root).get("preflight_max_risk", 70) else 0


def cmd_doctor(root: Path, json_output: bool) -> int:
    snap = collect_snapshot(root)
    reqs = doctor(snap)
    if json_output:
        print(json.dumps([asdict(r) for r in reqs], indent=2))
    else:
        print(f"Project families: {', '.join(snap['project']['families']) or 'generic/unknown'}")
        for r in reqs:
            print(f"[{r.status.upper():7}] {r.capability:<28} {r.evidence}")
            if r.status != "ok": print(f"          -> {r.recommendation}")
    return 1 if any(r.status == "missing" for r in reqs) else 0


def cmd_record(root: Path, result: str, stage: str, note: str) -> int:
    try: event = record_outcome(root, result, stage, note)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr); return 2
    print(f"Recorded {result} for stage '{stage}' at risk={event['risk']}/100.")
    return 0


def read_log_bounded(path: Path, max_bytes: int = 5_000_000) -> str:
    size = path.stat().st_size
    with path.open("rb") as f:
        if size <= max_bytes:
            data = f.read()
        else:
            half = max_bytes // 2
            head = f.read(half)
            f.seek(max(0, size - half))
            tail = f.read(half)
            data = head + b"\n\n--- DRIFTGUARD: LOG MIDDLE OMITTED ---\n\n" + tail
    return data.decode("utf-8", errors="replace")


def cmd_analyze_log(root: Path, log_file: Path, json_output: bool, save: bool) -> int:
    if not log_file.exists() or not log_file.is_file():
        print(f"Log file not found: {log_file}", file=sys.stderr)
        return 2
    report = None
    try:
        report = make_report(root)
    except FileNotFoundError:
        pass
    text = read_log_bounded(log_file, int(get_config(root).get("max_capture_bytes", 5_000_000)))
    diagnosis = analyze_log_text(text, report, str(log_file.resolve()))
    if save:
        incident = save_incident(root, diagnosis, log_path=str(log_file.resolve()))
        diagnosis["saved_incident_timestamp"] = incident["timestamp"]
    if json_output:
        print(json.dumps(diagnosis, indent=2))
    else:
        print_diagnosis(diagnosis)
    return 1 if (diagnosis.get("primary") or {}).get("severity") in {"critical", "high"} else 0


def cmd_incidents(root: Path, limit: int, json_output: bool) -> int:
    rows = load_recent_incidents(root, limit)
    if json_output:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("No classified incidents recorded yet.")
        return 0
    print(f"Recent DriftGuard incidents ({len(rows)}):")
    for row in reversed(rows):
        cmd = " ".join(row.get("command") or []) or "manual log analysis"
        print(f"- {row.get('timestamp')} [{str(row.get('severity') or 'unknown').upper()}] {row.get('primary_signature') or 'unclassified'}")
        print(f"  command: {_clip(cmd, 120)}")
        if row.get("log_path"):
            print(f"  log    : {row.get('log_path')}")
    return 0


def run_command_with_capture(root: Path, command: List[str]) -> Tuple[int, float, str, str]:
    ensure_state(root)
    log_dir = state_path(root, LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S%f")
    log_path = log_dir / f"guard-{stamp}.log"
    max_bytes = int(get_config(root).get("max_capture_bytes", 5_000_000))
    tail = deque(maxlen=4000)
    written = 0
    truncated = False
    started = time.time()
    try:
        proc = subprocess.Popen(
            command, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as exc:
        msg = f"{exc}\n"
        log_path.write_text(msg, encoding="utf-8")
        return 127, round(time.time() - started, 3), str(log_path), msg

    with log_path.open("w", encoding="utf-8", errors="replace") as out:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            tail.append(line)
            encoded_len = len(line.encode("utf-8", errors="replace"))
            if written + encoded_len <= max_bytes:
                out.write(line)
                written += encoded_len
            elif not truncated:
                out.write("\n--- DRIFTGUARD: CAPTURE TRUNCATED; LIVE OUTPUT CONTINUED ---\n")
                truncated = True
        rc = proc.wait()
    elapsed = round(time.time() - started, 3)
    return rc, elapsed, str(log_path), "".join(tail)


def cmd_guard(root: Path, command: List[str], max_risk: Optional[int], force: bool, capture: bool) -> int:
    if command and command[0] == "--": command = command[1:]
    if not command:
        print("No command supplied. Example: driftguard guard --capture -- python -m pytest", file=sys.stderr)
        return 2
    try: report = make_report(root)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr); return 2
    threshold = int(max_risk if max_risk is not None else get_config(root).get("preflight_max_risk", 70))
    risk = report["prediction"]["risk"]
    print(f"Preflight risk: {risk}/100 ({report['prediction']['label']}), threshold={threshold}")
    if risk >= threshold and not force:
        print("Command blocked by preflight risk threshold. Review `driftguard check`, or rerun guard with --force.")
        return 3
    print("Running:", " ".join(shlex.quote(x) for x in command))

    diagnosis = None
    log_path = None
    if capture:
        rc, elapsed, log_path, captured_tail = run_command_with_capture(root, command)
        if rc != 0:
            # Re-read the bounded stored log and append the tail so a truncated capture still includes final errors.
            try:
                captured = read_log_bounded(Path(log_path), int(get_config(root).get("max_capture_bytes", 5_000_000)))
            except Exception:
                captured = captured_tail
            if captured_tail and captured_tail not in captured:
                captured += "\n" + captured_tail
            diagnosis = analyze_log_text(captured, report, log_path)
            save_incident(root, diagnosis, command=command, exit_code=rc, log_path=log_path)
            print_diagnosis(diagnosis)
    else:
        started = time.time()
        try:
            rc = subprocess.call(command, cwd=str(root))
        except FileNotFoundError:
            rc = 127
        elapsed = round(time.time() - started, 3)

    result = "success" if rc == 0 else "failure"
    record_outcome(
        root, result, "guarded-command", f"duration={elapsed}s", command=command,
        exit_code=rc, diagnosis=diagnosis, log_path=log_path, report=report,
    )
    if log_path:
        print(f"Captured log: {log_path}")
    print(f"Outcome recorded: {result} (exit={rc}, {elapsed}s)")
    return rc

def cmd_export(root: Path, output: Path) -> int:
    report = make_report(root)
    output.write_text(report_html(root, report), encoding="utf-8")
    print(f"HTML report written: {output.resolve()}")
    return 0


def cmd_watch(root: Path, interval: int) -> int:
    print(f"Watching {root.resolve()} every {interval}s. Ctrl+C to stop.")
    last_signature = None
    try:
        while True:
            report = make_report(root)
            signature = (report["status"], report["score"], report["prediction"]["risk"],
                         tuple((f["severity"], f["item"], f["current"]) for f in report["findings"]))
            if signature != last_signature:
                print_report(report); last_signature = signature
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_serve(root: Path, port: int) -> int:
    try: make_report(root)
    except FileNotFoundError:
        print("No baseline. Run: driftguard init", file=sys.stderr); return 2

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                report = make_report(root)
                if self.path.startswith("/api/report"):
                    body = json.dumps(report, indent=2).encode(); ctype = "application/json; charset=utf-8"
                else:
                    body = report_html(root, report).encode(); ctype = "text/html; charset=utf-8"
                self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            except Exception as exc:
                body = str(exc).encode(); self.send_response(500); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.end_headers(); self.wfile.write(body)
        def log_message(self, fmt, *args): return

    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"DriftGuard dashboard: http://127.0.0.1:{port}\nCtrl+C to stop.")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
    return 0



# ---------------------------------------------------------------------------
# DriftGuard 4: native-system inventory, dependency graph intelligence,
# binary dependency inspection, and subsystem-level failure prediction.
# ---------------------------------------------------------------------------

def _safe_json_from_command(cmd: Sequence[str], timeout: int = 8) -> Any:
    out = run(cmd, timeout=timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def gpu_driver_inventory() -> List[dict]:
    """Best-effort GPU identity + driver fingerprint without third-party packages."""
    rows: List[dict] = []
    try:
        if os.name == "nt":
            ps = (
                "Get-CimInstance Win32_VideoController | "
                "Select-Object Name,DriverVersion,PNPDeviceID,AdapterRAM | ConvertTo-Json -Compress"
            )
            data = _safe_json_from_command(["powershell", "-NoProfile", "-Command", ps], timeout=8)
            if isinstance(data, dict):
                data = [data]
            for x in data or []:
                rows.append({
                    "name": x.get("Name"), "driver_version": x.get("DriverVersion"),
                    "device_id": x.get("PNPDeviceID"), "adapter_ram": x.get("AdapterRAM"),
                })
        elif sys.platform.startswith("linux"):
            out = run(["nvidia-smi", "--query-gpu=name,driver_version,pci.bus_id", "--format=csv,noheader,nounits"], timeout=7)
            if out:
                for line in out.splitlines():
                    parts = [x.strip() for x in line.split(",")]
                    if len(parts) >= 3:
                        rows.append({"name": parts[0], "driver_version": parts[1], "device_id": parts[2], "source": "nvidia-smi"})
            if not rows:
                out = run(["lspci", "-nnk"], timeout=7)
                if out:
                    current = None
                    for line in out.splitlines():
                        low = line.lower()
                        if ("vga compatible controller" in low or "3d controller" in low) and not line.startswith("\t"):
                            current = {"name": line.strip(), "driver_version": None, "device_id": None, "source": "lspci"}
                            rows.append(current)
                        elif current and "kernel driver in use:" in low:
                            current["kernel_driver"] = line.split(":", 1)[1].strip()
        elif sys.platform == "darwin":
            out = run(["system_profiler", "SPDisplaysDataType", "-json"], timeout=10)
            if out:
                try:
                    data = json.loads(out)
                    for x in data.get("SPDisplaysDataType", []):
                        rows.append({
                            "name": x.get("sppci_model") or x.get("_name"),
                            "driver_version": x.get("spdisplays_metal_version"),
                            "device_id": x.get("spdisplays_device-id"),
                            "source": "system_profiler",
                        })
                except Exception:
                    pass
    except Exception:
        pass
    return rows


def _versions_from_dir(path: Path, child_glob: str = "*") -> List[str]:
    try:
        if not path.exists():
            return []
        return sorted([p.name for p in path.glob(child_glob) if p.is_dir()])
    except Exception:
        return []


def unreal_installations() -> List[dict]:
    installs: List[dict] = []
    seen = set()
    candidates: List[Path] = []
    if os.name == "nt":
        data_path = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Epic" / "UnrealEngineLauncher" / "LauncherInstalled.dat"
        if data_path.exists():
            try:
                data = json.loads(data_path.read_text(encoding="utf-8", errors="ignore"))
                for item in data.get("InstallationList", []):
                    loc = item.get("InstallLocation")
                    app = item.get("AppName") or item.get("ArtifactId")
                    if loc and ("UE_" in str(app) or "Unreal" in str(app)):
                        key = str(Path(loc))
                        if key not in seen:
                            seen.add(key); installs.append({"version": app, "path": key, "source": "Epic Launcher"})
            except Exception:
                pass
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.extend((Path(base) / "Epic Games").glob("UE_*"))
    elif sys.platform == "darwin":
        candidates.extend(Path("/Users/Shared/Epic Games").glob("UE_*"))
    else:
        for base in [Path.home()/"UnrealEngine", Path.home()/"Epic Games", Path("/opt")]:
            if base.exists(): candidates.extend(base.glob("UE_*"))
    for p in candidates:
        try:
            if p.is_dir() and str(p) not in seen:
                seen.add(str(p)); installs.append({"version": p.name.replace("UE_", ""), "path": str(p), "source": "filesystem"})
        except Exception:
            pass
    return sorted(installs, key=lambda x: str(x.get("version")))


def unity_installations() -> List[dict]:
    bases: List[Path] = []
    if os.name == "nt":
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base: bases.append(Path(base) / "Unity" / "Hub" / "Editor")
    elif sys.platform == "darwin":
        bases.append(Path("/Applications/Unity/Hub/Editor"))
    else:
        bases.extend([Path.home()/"Unity"/"Hub"/"Editor", Path.home()/".local/share/UnityHub/Editor"])
    out = []
    for base in bases:
        for version in _versions_from_dir(base):
            out.append({"version": version, "path": str(base / version)})
    return out


def sdk_inventory() -> dict:
    env = os.environ
    dotnet_sdks = []
    out = run(["dotnet", "--list-sdks"], timeout=7)
    if out:
        for line in out.splitlines():
            m = re.match(r"([^\s]+)\s+\[(.+)\]", line.strip())
            dotnet_sdks.append({"version": m.group(1), "path": m.group(2)} if m else {"raw": line.strip()})

    android_root = env.get("ANDROID_SDK_ROOT") or env.get("ANDROID_HOME")
    android = {"root": android_root, "platforms": [], "build_tools": []}
    if android_root:
        ar = Path(android_root)
        android["platforms"] = _versions_from_dir(ar / "platforms")
        android["build_tools"] = _versions_from_dir(ar / "build-tools")

    cuda_root = env.get("CUDA_PATH")
    cuda = {"root": cuda_root, "nvcc": first_line(run(["nvcc", "--version"], timeout=6))}
    vulkan = {"root": env.get("VULKAN_SDK"), "runtime": first_line(run(["vulkaninfo", "--summary"], timeout=7))}
    java = {"java_home": env.get("JAVA_HOME"), "version": first_line(run(["java", "-version"], timeout=6))}

    return {
        "dotnet_sdks": dotnet_sdks,
        "java": java,
        "android": android,
        "cuda": cuda,
        "vulkan": vulkan,
        "visual_studio_cpp": windows_visual_studio(),
    }


def engine_inventory() -> dict:
    return {"unreal": unreal_installations(), "unity": unity_installations()}


def parse_requirements_graph(path: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)\s*(===|==|~=|>=|<=|>|<)?\s*([^;\s]+)?", line)
            if m:
                name = m.group(1).lower().replace("_", "-")
                deps[name] = ((m.group(2) or "") + (m.group(3) or "")).strip() or "unversioned"
    except Exception:
        pass
    return deps


def parse_package_lock_graph(path: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, val in packages.items():
                if not key.startswith("node_modules/") or not isinstance(val, dict):
                    continue
                name = key[len("node_modules/"):]
                if "/node_modules/" in name:
                    continue
                deps[name] = str(val.get("version") or "unknown")
        else:
            for name, val in (data.get("dependencies") or {}).items():
                if isinstance(val, dict): deps[name] = str(val.get("version") or "unknown")
    except Exception:
        pass
    return deps


def parse_cargo_lock_graph(path: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for block in re.split(r"\n\s*\[\[package\]\]\s*\n", text)[1:]:
            nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
            vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
            if nm and vm: deps[nm.group(1)] = vm.group(1)
    except Exception:
        pass
    return deps


def parse_go_sum_graph(path: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                mod, version = parts[0], parts[1].replace("/go.mod", "")
                deps.setdefault(mod, version)
    except Exception:
        pass
    return deps


def dependency_graph(root: Path, project_files: Dict[str, dict], sample_limit: int = 250) -> dict:
    groups: Dict[str, Dict[str, str]] = {}
    for rel in project_files:
        p = root / rel
        name = p.name
        if name.startswith("requirements") and name.endswith(".txt"):
            groups.setdefault("python", {}).update(parse_requirements_graph(p))
        elif name == "package-lock.json":
            groups.setdefault("node", {}).update(parse_package_lock_graph(p))
        elif name == "Cargo.lock":
            groups.setdefault("rust", {}).update(parse_cargo_lock_graph(p))
        elif name == "go.sum":
            groups.setdefault("go", {}).update(parse_go_sum_graph(p))
    canonical = []
    samples = {}
    total = 0
    for eco in sorted(groups):
        items = sorted(groups[eco].items())
        total += len(items)
        canonical.extend(f"{eco}:{k}={v}" for k, v in items)
        samples[eco] = [{"name": k, "version": v} for k, v in items[:sample_limit]]
    fp = hashlib.sha256("\n".join(canonical).encode()).hexdigest() if canonical else None
    return {"fingerprint": fp, "dependency_count": total, "ecosystems": sorted(groups), "packages": samples}


def _rva_to_offset(rva: int, sections: List[Tuple[int, int, int, int]]) -> Optional[int]:
    for va, vsize, raw, rawsize in sections:
        span = max(vsize, rawsize)
        if va <= rva < va + span:
            return raw + (rva - va)
    return None


def pe_imports(path: Path, max_imports: int = 256) -> List[str]:
    """Parse PE import DLL names using only struct; intentionally bounded."""
    try:
        data = path.read_bytes()
        if len(data) < 0x100 or data[:2] != b"MZ":
            return []
        peoff = struct.unpack_from("<I", data, 0x3C)[0]
        if peoff + 24 >= len(data) or data[peoff:peoff+4] != b"PE\0\0":
            return []
        nsects = struct.unpack_from("<H", data, peoff + 6)[0]
        opt_size = struct.unpack_from("<H", data, peoff + 20)[0]
        opt = peoff + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        dd = opt + (112 if magic == 0x20B else 96 if magic == 0x10B else -1)
        if dd < opt or dd + 16 > len(data): return []
        import_rva, _import_size = struct.unpack_from("<II", data, dd + 8)
        sec = opt + opt_size
        sections = []
        for i in range(min(nsects, 96)):
            off = sec + i * 40
            if off + 40 > len(data): break
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, off + 8)
            sections.append((va, vsize, raw, rawsize))
        imp_off = _rva_to_offset(import_rva, sections)
        if imp_off is None: return []
        imports = []
        for i in range(max_imports):
            off = imp_off + i * 20
            if off + 20 > len(data): break
            vals = struct.unpack_from("<IIIII", data, off)
            if not any(vals): break
            name_off = _rva_to_offset(vals[3], sections)
            if name_off is None or name_off >= len(data): continue
            end = data.find(b"\0", name_off, min(len(data), name_off + 512))
            if end == -1: continue
            name = data[name_off:end].decode("ascii", errors="ignore").strip()
            if name: imports.append(name)
        return sorted(set(imports), key=str.lower)
    except Exception:
        return []


def binary_dependencies(path: Path) -> List[str]:
    suffix = path.suffix.lower()
    if suffix in {".dll", ".exe"}:
        imports = pe_imports(path)
        if imports: return imports
    if sys.platform.startswith("linux") and (suffix in {".so", ".elf"} or os.access(path, os.X_OK)):
        out = run(["ldd", str(path)], timeout=5)
        if out:
            return sorted(set(x.strip() for x in out.splitlines() if x.strip()))[:256]
    if sys.platform == "darwin" and suffix in {".dylib", ""}:
        out = run(["otool", "-L", str(path)], timeout=5)
        if out:
            return sorted(set(x.strip() for x in out.splitlines()[1:] if x.strip()))[:256]
    return []


def native_artifact_inventory(root: Path, max_artifacts: int = 120, max_inspections: int = 30) -> dict:
    artifacts = []
    inspected = 0
    skip = {".git", STATE_DIR, "node_modules", ".venv", "venv", "DerivedDataCache", "Library"}
    native_suffixes = {".dll", ".so", ".dylib", ".exe", ".elf"}
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in names:
            p = Path(base) / name
            if p.suffix.lower() not in native_suffixes:
                continue
            try:
                stat = p.stat()
                rel = str(p.relative_to(root)).replace("\\", "/")
                rec = {"path": rel, "size": stat.st_size, "sha256": sha256_file(p)}
                if inspected < max_inspections and stat.st_size <= 512 * 1024 * 1024:
                    deps = binary_dependencies(p)
                    if deps: rec["dependencies"] = deps
                    inspected += 1
                artifacts.append(rec)
                if len(artifacts) >= max_artifacts:
                    return {"artifacts": artifacts, "truncated": True, "inspected_dependencies": inspected}
            except OSError:
                pass
    return {"artifacts": artifacts, "truncated": False, "inspected_dependencies": inspected}


def native_inventory(root: Path, project_files: Optional[Dict[str, dict]] = None) -> dict:
    cfg = get_config(root)
    project_files = project_files if project_files is not None else discover_project_files(root, int(cfg.get("max_scan_depth", 5)))
    return {
        "gpu_drivers": gpu_driver_inventory(),
        "sdks": sdk_inventory(),
        "engines": engine_inventory(),
        "dependency_graph": dependency_graph(root, project_files, int(cfg.get("dependency_sample_limit", 250))),
        "native_artifacts": native_artifact_inventory(
            root, int(cfg.get("max_native_artifacts", 120)), int(cfg.get("max_native_dependency_inspections", 30))
        ),
    }


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def collect_snapshot(root: Path) -> dict:
    """v4 snapshot overrides v3 with exact native/SDK inventory."""
    cfg = get_config(root)
    tools = {}
    for name, cmd in TOOL_COMMANDS.items():
        out = run(cmd)
        exe = cmd[0]
        tools[name] = {
            "present": out is not None,
            "version": first_line(out),
            "path": shutil.which(exe) if exe != sys.executable else sys.executable,
        }
    env = {key: os.environ.get(key) for key in IMPORTANT_ENV if os.environ.get(key)}
    files = discover_project_files(root, int(cfg.get("max_scan_depth", 5)))
    shape = scan_source_shape(root, int(cfg.get("max_scan_depth", 5)), int(cfg.get("max_source_files", 25000)))
    project = infer_project(root, files, shape)
    native = native_inventory(root, files)
    return {
        "schema": 4,
        "app_version": APP_VERSION,
        "timestamp": now_iso(),
        "project_root": str(root.resolve()),
        "host": {
            "hostname": socket.gethostname(), "os": platform.system(),
            "os_release": platform.release(), "os_version": platform.version(),
            "machine": platform.machine(), "processor": platform.processor(),
            "python_implementation": platform.python_implementation(),
            "ram_bytes": get_ram_bytes(), "gpu": get_gpu(),
            "gpu_driver_fingerprint": _fingerprint(native.get("gpu_drivers", [])),
        },
        "tools": tools,
        "visual_studio_cpp": native.get("sdks", {}).get("visual_studio_cpp", {}),
        "environment": env,
        "project_files": files,
        "project": project,
        "native": native,
        "git": get_git_state(root),
    }


def compare(baseline: dict, current: dict) -> List[Finding]:
    """v4 comparison: preserve v3 semantics and add native/dependency intelligence."""
    findings: List[Finding] = []
    bh, ch = baseline.get("host", {}), current.get("host", {})
    if bh.get("os") != ch.get("os"):
        add(findings, "critical", "host", "operating system", bh.get("os"), ch.get("os"), "Project moved to a different operating-system family.", "Rebuild native dependencies and validate platform-specific code/configuration.")
    if bh.get("machine") != ch.get("machine"):
        add(findings, "critical", "host", "architecture", bh.get("machine"), ch.get("machine"), "CPU architecture changed.", "Rebuild native artifacts and verify architecture-specific dependencies.")
    if bh.get("gpu") and ch.get("gpu") and bh.get("gpu") != ch.get("gpu"):
        add(findings, "medium", "hardware", "GPU", bh.get("gpu"), ch.get("gpu"), "Graphics hardware identity changed.", "Revalidate graphics/compute workloads, shaders, drivers, and VRAM assumptions.")
    if bh.get("gpu_driver_fingerprint") and ch.get("gpu_driver_fingerprint") and bh.get("gpu_driver_fingerprint") != ch.get("gpu_driver_fingerprint"):
        add(findings, "high", "hardware", "GPU driver stack", bh.get("gpu_driver_fingerprint")[:12], ch.get("gpu_driver_fingerprint")[:12], "GPU driver fingerprint changed.", "Revalidate CUDA/Vulkan/DirectX/OpenGL workloads and shader/compute caches before release builds.")

    btools, ctools = baseline.get("tools", {}), current.get("tools", {})
    for name in sorted(set(btools) | set(ctools)):
        b, c = btools.get(name, {}), ctools.get(name, {})
        if b.get("present") and not c.get("present"):
            add(findings, "high", "toolchain", name, b.get("version"), None, f"Required previously-present tool '{name}' disappeared.", f"Restore {name} or update the project so it no longer depends on it.")
        elif not b.get("present") and c.get("present"):
            add(findings, "info", "toolchain", name, None, c.get("version"), f"New tool '{name}' is now installed.", "No action required unless build selection changed.")
        elif b.get("present") and c.get("present"):
            compare_versions(name, b.get("version"), c.get("version"), findings)
            if b.get("path") and c.get("path") and b.get("path") != c.get("path"):
                add(findings, "medium", "toolchain", name + " path", b.get("path"), c.get("path"), f"{name} resolves to a different executable.", "Confirm PATH/toolchain selection is intentional.")

    benv, cenv = baseline.get("environment", {}), current.get("environment", {})
    for key in sorted(set(benv) | set(cenv)):
        if benv.get(key) != cenv.get(key):
            add(findings, "medium", "environment", key, benv.get(key), cenv.get(key), f"Build-related environment variable {key} changed.", "Check whether this redirects the SDK, compiler, or package manager.")

    bfiles, cfiles = baseline.get("project_files", {}), current.get("project_files", {})
    for path in sorted(set(bfiles) | set(cfiles)):
        b, c = bfiles.get(path), cfiles.get(path)
        if b and not c:
            add(findings, "high", "project", path, b.get("sha256", "")[:12], None, "Tracked build/dependency file was removed.", "Confirm deletion is intentional and replacement configuration is committed.")
        elif not b and c:
            add(findings, "medium", "project", path, None, c.get("sha256", "")[:12], "New build/dependency file appeared.", "Review it for a new package manager, build path, or source of version truth.")
        elif b and c and b.get("sha256") != c.get("sha256"):
            lockish = any(x in Path(path).name.lower() for x in ("lock", "sum"))
            add(findings, "high" if lockish else "medium", "project", path, b.get("sha256", "")[:12], c.get("sha256", "")[:12], "Dependency/build manifest changed.", "Re-resolve dependencies if needed and run the project's build/test suite.")
        if b and c and path.endswith(".uproject") and b.get("engine_association") != c.get("engine_association"):
            add(findings, "high", "engine", path, b.get("engine_association"), c.get("engine_association"), "Unreal Engine association changed.", "Open with the intended engine, regenerate project files, then rebuild C++ modules/plugins.")

    bn, cn = baseline.get("native", {}), current.get("native", {})
    bg, cg = bn.get("dependency_graph", {}), cn.get("dependency_graph", {})
    if bg.get("fingerprint") and cg.get("fingerprint") and bg.get("fingerprint") != cg.get("fingerprint"):
        bcount, ccount = bg.get("dependency_count", 0), cg.get("dependency_count", 0)
        add(findings, "high", "dependencies", "resolved dependency graph", f"{bcount} deps / {bg.get('fingerprint','')[:12]}", f"{ccount} deps / {cg.get('fingerprint','')[:12]}", "Resolved dependency graph changed.", "Review package-level changes and run the smallest relevant dependency/build validation before a full build.")

    bsdks, csdks = bn.get("sdks", {}), cn.get("sdks", {})
    for key in ("dotnet_sdks", "java", "android", "cuda", "vulkan", "visual_studio_cpp"):
        if key in bsdks and key in csdks and _fingerprint(bsdks.get(key)) != _fingerprint(csdks.get(key)):
            add(findings, "medium", "sdk", key, _fingerprint(bsdks.get(key))[:12], _fingerprint(csdks.get(key))[:12], f"{key} inventory changed.", "Confirm the project still resolves the intended SDK/toolset version and run a targeted validation.")

    beng, ceng = bn.get("engines", {}), cn.get("engines", {})
    if beng and ceng and _fingerprint(beng) != _fingerprint(ceng):
        add(findings, "medium", "engine", "installed engine inventory", _fingerprint(beng)[:12], _fingerprint(ceng)[:12], "Installed game-engine inventory changed.", "Verify the project opens with its intended engine version before migrating assets or native modules.")

    bart = {x.get("path"): x for x in bn.get("native_artifacts", {}).get("artifacts", [])}
    cart = {x.get("path"): x for x in cn.get("native_artifacts", {}).get("artifacts", [])}
    changed_artifacts = [p for p in set(bart) & set(cart) if bart[p].get("sha256") != cart[p].get("sha256")]
    removed_artifacts = [p for p in set(bart) - set(cart)]
    if changed_artifacts:
        add(findings, "medium", "native", "native binary set", f"{len(bart)} baseline artifacts", f"{len(changed_artifacts)} changed", "Native binaries changed since the known-good baseline.", "Check ABI/toolset compatibility and inspect imported shared libraries before shipping or debugging higher layers.")
    if removed_artifacts:
        add(findings, "high", "native", "missing native artifacts", len(removed_artifacts), 0, "Previously tracked native artifacts disappeared.", "Rebuild or restore the missing native outputs before runtime/package validation.")

    bgit, cgit = baseline.get("git", {}), current.get("git", {})
    if bgit.get("is_repo") and cgit.get("is_repo") and bgit.get("branch") != cgit.get("branch"):
        add(findings, "info", "git", "branch", bgit.get("branch"), cgit.get("branch"), "Git branch changed since baseline.", "Informational: branch-specific baselines may be useful if environments intentionally differ.")

    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.item))


def correlate_drift(signature: LogSignature, report: Optional[dict]) -> List[dict]:
    """v4 causal correlation avoids generic category terms that create false links."""
    if not report:
        return []
    generic = {"project", "environment", "host", "sdk", "path", "engine", "compiler"}
    explicit_terms = {x.lower() for x in signature.drift_terms if x.lower() not in generic}
    ecosystem_affinity = {
        "cpp": {"native", "toolchain", "sdk", "hardware"},
        "unreal": {"engine", "native", "toolchain", "sdk"},
        "cuda": {"hardware", "sdk", "toolchain", "environment", "native"},
        "vulkan": {"hardware", "sdk", "environment", "native"},
        "python": {"toolchain", "dependencies", "native", "project"},
        "node": {"toolchain", "dependencies", "project"},
        "android": {"sdk", "toolchain", "environment", "project"},
        "dotnet": {"sdk", "toolchain", "project"},
        "rust": {"toolchain", "native", "project"},
        "go": {"toolchain", "dependencies", "project"},
        "docker": {"toolchain", "environment"},
        "system": {"host", "hardware", "environment"},
    }.get(signature.ecosystem.lower(), set())
    correlated = []
    seen = set()
    for f in report.get("findings", []):
        item = str(f.get("item", ""))
        if item in seen:
            continue
        detail = " ".join(str(f.get(k, "")) for k in ("item", "baseline", "current", "message", "recommendation")).lower()
        matched = sorted(t for t in explicit_terms if t and t in detail)
        category = str(f.get("category", "")).lower()
        affinity = category in ecosystem_affinity
        # Require concrete term evidence or a domain-specific category affinity.
        # For broad project/dependency findings, concrete terms are mandatory.
        if matched or (affinity and category not in {"project", "dependencies"}):
            seen.add(item)
            correlated.append({
                "severity": f.get("severity"), "item": f.get("item"), "message": f.get("message"),
                "matched_terms": matched, "category_affinity": affinity,
            })
    correlated.sort(key=lambda x: -SEVERITY_ORDER.get(str(x.get("severity")), 0))
    return correlated[:5]


def subsystem_prediction(root: Path, report: dict, requirements: List[Requirement]) -> dict:
    findings = report.get("findings", [])
    incidents = load_recent_incidents(root, 60)
    events = read_jsonl(state_path(root, EVENTS_FILE))[-80:]
    families = set(report.get("current", {}).get("project", {}).get("families", []))
    buckets = {
        "toolchain": {"score": 3, "evidence": [], "validate": "driftguard doctor"},
        "dependencies": {"score": 3, "evidence": [], "validate": None},
        "native_abi": {"score": 2, "evidence": [], "validate": None},
        "graphics_gpu": {"score": 2, "evidence": [], "validate": None},
        "game_engine": {"score": 2, "evidence": [], "validate": None},
        "mobile_sdk": {"score": 2, "evidence": [], "validate": None},
        "containers": {"score": 2, "evidence": [], "validate": None},
        "resources": {"score": 2, "evidence": [], "validate": None},
    }
    sev_weight = {"critical": 48, "high": 28, "medium": 14, "low": 5, "info": 0}
    def bump(bucket: str, amount: int, evidence: str):
        b = buckets[bucket]; b["score"] = min(100, b["score"] + amount); b["evidence"].append(evidence)

    for f in findings:
        cat, item, sev = str(f.get("category", "")), str(f.get("item", "")), str(f.get("severity", "medium"))
        w = sev_weight.get(sev, 10)
        text = (cat + " " + item + " " + str(f.get("message", ""))).lower()
        if any(x in text for x in ("dependency", "requirements", "lock", "package", "go.sum", "cargo")): bump("dependencies", w, f"{sev}: {item}")
        if any(x in text for x in ("compiler", "toolchain", "cmake", "python", "node", "java", "dotnet", "path")): bump("toolchain", w, f"{sev}: {item}")
        if any(x in text for x in ("native", "architecture", "abi", "msvc", "dll", "binary")): bump("native_abi", w, f"{sev}: {item}")
        if any(x in text for x in ("gpu", "cuda", "vulkan", "driver")): bump("graphics_gpu", w, f"{sev}: {item}")
        if any(x in text for x in ("unreal", "unity", "engine")): bump("game_engine", w, f"{sev}: {item}")
        if any(x in text for x in ("android", "gradle")): bump("mobile_sdk", w, f"{sev}: {item}")
        if "docker" in text: bump("containers", w, f"{sev}: {item}")

    for r in requirements:
        if r.status == "ok": continue
        t = (r.capability + " " + r.evidence).lower(); w = 32 if r.status == "missing" else 14
        if any(x in t for x in ("cuda", "vulkan", "gpu")): bump("graphics_gpu", w, f"{r.status}: {r.capability}")
        elif any(x in t for x in ("unreal", "unity")): bump("game_engine", w, f"{r.status}: {r.capability}")
        elif "android" in t or "gradle" in t: bump("mobile_sdk", w, f"{r.status}: {r.capability}")
        elif "docker" in t: bump("containers", w, f"{r.status}: {r.capability}")
        else: bump("toolchain", w, f"{r.status}: {r.capability}")

    signature_to_bucket = {
        "python.module-missing": "dependencies", "node.resolve": "dependencies", "go.module": "dependencies",
        "python.native-load": "native_abi", "msvc.unresolved-symbol": "native_abi", "msvc.runtime-mismatch": "native_abi",
        "native.undefined-reference": "native_abi", "native.architecture": "native_abi",
        "cuda.driver-toolkit": "graphics_gpu", "cuda.compiler": "graphics_gpu", "vulkan.driver": "graphics_gpu",
        "unreal.engine-version": "game_engine", "unreal.build-tool": "game_engine",
        "gradle.java": "mobile_sdk", "docker.daemon": "containers",
        "resource.disk": "resources", "resource.memory": "resources",
        "cmake.compiler": "toolchain", "cmake.package": "dependencies", "dotnet.sdk": "toolchain", "rust.link": "toolchain",
    }
    for incident in incidents[-20:]:
        sig = incident.get("primary_signature")
        bucket = signature_to_bucket.get(sig)
        if bucket:
            sev = str(incident.get("severity") or "high")
            incident_weight = {"critical": 30, "high": 20, "medium": 12, "low": 6, "info": 2}.get(sev, 12)
            bump(bucket, incident_weight, f"incident: {sig}")

    # Give validation commands that are useful before the expensive full build.
    if "python" in families: buckets["dependencies"]["validate"] = f'"{sys.executable}" -m pip check'
    if "node" in families: buckets["dependencies"]["validate"] = "npm ls --depth=0"
    if "rust" in families: buckets["toolchain"]["validate"] = "cargo check"
    if "go" in families: buckets["dependencies"]["validate"] = "go test ./..."
    if "cpp" in families: buckets["native_abi"]["validate"] = "cmake --build build --config Debug"
    if "unreal" in families: buckets["game_engine"]["validate"] = "Regenerate project files, then compile the Editor target for the intended EngineAssociation"
    if "unity" in families: buckets["game_engine"]["validate"] = "Open once in the pinned Unity editor and run a batchmode compile/test pass"
    if "cuda" in families: buckets["graphics_gpu"]["validate"] = "nvcc --version && nvidia-smi"
    if "vulkan" in families: buckets["graphics_gpu"]["validate"] = "vulkaninfo --summary"
    if "android" in families: buckets["mobile_sdk"]["validate"] = "gradlew tasks"
    if "docker" in families: buckets["containers"]["validate"] = "docker version"

    ranked = []
    for name, data in buckets.items():
        score = max(0, min(100, int(data["score"])))
        if score < 20: label = "LOW"
        elif score < 45: label = "GUARDED"
        elif score < 70: label = "ELEVATED"
        else: label = "HIGH"
        ranked.append({"subsystem": name, "risk": score, "label": label,
                       "evidence": data["evidence"][:8], "validation": data.get("validate")})
    ranked.sort(key=lambda x: (-x["risk"], x["subsystem"]))
    history_n = sum(1 for e in events if e.get("result") in {"success", "failure"})
    confidence = "HIGH" if history_n >= 20 else ("MEDIUM" if history_n >= 6 or incidents else "LOW")
    return {"confidence": confidence, "most_at_risk": ranked[0] if ranked else None, "subsystems": ranked}


def predict_risk(root: Path, report: dict, requirements: List[Requirement]) -> dict:
    """v4 overall predictor retains historical model and adds subsystem signal."""
    events = read_jsonl(state_path(root, EVENTS_FILE))
    findings = report.get("findings", [])
    drift_component = min(1.0, (100 - report.get("score", 100)) / 70.0)
    missing = [r for r in requirements if r.status == "missing"]
    warnings = [r for r in requirements if r.status == "warning"]
    requirement_component = min(1.0, (len(missing) * 0.45) + (len(warnings) * 0.12))
    failures = sum(1 for e in events if e.get("result") == "failure")
    successes = sum(1 for e in events if e.get("result") == "success")
    n = failures + successes
    prior_failure = (failures + 1) / (n + 2) if n else 0.15
    current_keys = {finding_key(f) for f in findings}
    assoc_values = []
    for key in sorted(current_keys):
        rel = [e for e in events if key in set(e.get("finding_keys", []))]
        if rel:
            fcount = sum(1 for e in rel if e.get("result") == "failure")
            assoc_values.append(((fcount + 1) / (len(rel) + 2), key))
    association_component = max([prob for prob, _ in assoc_values], default=prior_failure)
    recent = [e for e in events[-10:] if e.get("result") in {"success", "failure"}]
    recent_fail_rate = (sum(1 for e in recent if e.get("result") == "failure") / len(recent)) if recent else prior_failure
    history_component = 0.65 * association_component + 0.35 * recent_fail_rate
    recent_failed = [e for e in events[-12:] if e.get("result") == "failure"]
    signature_counts = Counter(sig for e in recent_failed for sig in (e.get("failure_signatures") or []) if sig)
    signature_component = min(1.0, sum(signature_counts.values()) / 6.0)
    if recent and recent[-1].get("result") == "success": signature_component *= 0.65

    subsystem = subsystem_prediction(root, report, requirements)
    top_subsystem_risk = (subsystem.get("most_at_risk") or {}).get("risk", 0) / 100.0
    raw = 100 * (0.40 * drift_component + 0.22 * requirement_component + 0.18 * history_component + 0.08 * signature_component + 0.12 * top_subsystem_risk)
    if any(f.get("severity") == "critical" for f in findings): raw = max(raw, 82)
    if len(missing) >= 2: raw = max(raw, 72)
    risk = max(0, min(100, round(raw)))
    label = "LOW" if risk < 20 else "GUARDED" if risk < 45 else "ELEVATED" if risk < 70 else "HIGH"
    confidence = "HIGH" if n >= 20 else ("MEDIUM" if n >= 6 or subsystem.get("confidence") == "MEDIUM" else "LOW")
    drivers = []
    for f in findings[:5]:
        if f.get("severity") != "info": drivers.append({"type": "drift", "severity": f.get("severity"), "item": f.get("item"), "detail": f.get("message")})
    for r in missing[:4]: drivers.append({"type": "requirement", "severity": r.severity, "item": r.capability, "detail": r.recommendation})
    for sig, count in signature_counts.most_common(3): drivers.append({"type": "failure-signature", "severity": "high", "item": sig, "detail": f"Observed {count} time(s) in recent failed guarded commands."})
    if subsystem.get("most_at_risk"):
        m = subsystem["most_at_risk"]
        drivers.append({"type": "subsystem", "severity": "high" if m["risk"] >= 70 else "medium", "item": m["subsystem"], "detail": f"Subsystem risk {m['risk']}/100; validate first with: {m.get('validation') or 'targeted project check'}"})
    if n: drivers.append({"type": "history", "severity": "info", "item": "recorded-build-history", "detail": f"{failures} failures / {n} outcomes; recent failure rate {recent_fail_rate:.0%}."})
    return {
        "risk": risk, "label": label, "confidence": confidence, "recorded_outcomes": n,
        "historical_failure_rate": round(prior_failure, 4), "recent_failure_signatures": dict(signature_counts.most_common(8)),
        "components": {"drift": round(drift_component, 4), "requirements": round(requirement_component, 4), "history": round(history_component, 4), "failure_signatures": round(signature_component, 4), "subsystem": round(top_subsystem_risk, 4)},
        "drivers": drivers, "subsystem_prediction": subsystem,
    }


def make_report(root: Path) -> dict:
    baseline_path = state_path(root, BASELINE_FILE)
    if not baseline_path.exists(): raise FileNotFoundError("No baseline. Run: driftguard init")
    baseline = load_json(baseline_path)
    current = collect_snapshot(root)
    findings = compare(baseline, current)
    score_value = stability_score(findings)
    reqs = doctor(current)
    report = {
        "schema": 4, "generated_at": now_iso(), "project_root": str(root.resolve()),
        "baseline_timestamp": baseline.get("timestamp"), "score": score_value,
        "status": stability_status(score_value, findings),
        "counts": {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in findings], "requirements": [asdict(r) for r in reqs],
        "current": current,
        "recent_incidents": load_recent_incidents(root, int(get_config(root).get("incident_history_limit", 100)))[-8:],
    }
    report["prediction"] = predict_risk(root, report, reqs)
    ensure_state(root); write_json(state_path(root, LAST_REPORT_FILE), report)
    append_jsonl(state_path(root, HISTORY_FILE), {"timestamp": report["generated_at"], "score": report["score"], "status": report["status"], "risk": report["prediction"]["risk"], "risk_label": report["prediction"]["label"], "counts": report["counts"]})
    return report


def cmd_inventory(root: Path, json_output: bool) -> int:
    snap = collect_snapshot(root)
    native = snap.get("native", {})
    if json_output:
        print(json.dumps(native, indent=2)); return 0
    print("DriftGuard native/system inventory")
    print("=" * 78)
    print("GPU drivers:")
    for x in native.get("gpu_drivers", []) or []:
        print(f"  - {x.get('name') or 'unknown'} | driver {x.get('driver_version') or '?'} | {x.get('device_id') or ''}")
    print("SDKs:")
    sdks = native.get("sdks", {})
    print(f"  .NET SDKs : {', '.join(x.get('version','?') for x in sdks.get('dotnet_sdks', []) if isinstance(x, dict)) or 'none detected'}")
    print(f"  Java      : {sdks.get('java',{}).get('version') or 'not detected'}")
    print(f"  Android   : {sdks.get('android',{}).get('root') or 'not detected'}")
    print(f"  CUDA      : {sdks.get('cuda',{}).get('nvcc') or 'not detected'}")
    print(f"  Vulkan    : {sdks.get('vulkan',{}).get('root') or 'not detected'}")
    print("Engines:")
    for name, rows in native.get("engines", {}).items():
        print(f"  {name}: {', '.join(str(x.get('version')) for x in rows) if rows else 'none detected'}")
    graph = native.get("dependency_graph", {})
    print(f"Dependency graph: {graph.get('dependency_count',0)} resolved entries | fingerprint {(graph.get('fingerprint') or 'none')[:16]}")
    arts = native.get("native_artifacts", {})
    print(f"Native artifacts: {len(arts.get('artifacts',[]))} found | {arts.get('inspected_dependencies',0)} dependency tables inspected")
    return 0


def cmd_subsystems(root: Path, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e: print(str(e), file=sys.stderr); return 2
    data = report.get("prediction", {}).get("subsystem_prediction", {})
    if json_output: print(json.dumps(data, indent=2)); return 0
    print(f"Subsystem prediction confidence: {data.get('confidence','LOW')}")
    for x in data.get("subsystems", []):
        print(f"[{x['label']:<8}] {x['subsystem']:<16} {x['risk']:>3}/100")
        if x.get("evidence"): print("           " + "; ".join(x["evidence"][:3]))
        if x.get("validation"): print(f"           validate: {x['validation']}")
    return 1 if (data.get("most_at_risk") or {}).get("risk", 0) >= 70 else 0


def cmd_native_scan(root: Path, json_output: bool) -> int:
    cfg = get_config(root)
    data = native_artifact_inventory(root, int(cfg.get("max_native_artifacts",120)), int(cfg.get("max_native_dependency_inspections",30)))
    if json_output: print(json.dumps(data, indent=2)); return 0
    for a in data.get("artifacts", []):
        print(f"{a['path']}  {a['size']} bytes  {a['sha256'][:12]}")
        for d in a.get("dependencies", [])[:20]: print(f"    -> {d}")
    if data.get("truncated"): print("[truncated by configured artifact limit]")
    return 0


# ---------------------------------------------------------------------------
# DriftGuard v5: structural failure graph and node-level prediction
# ---------------------------------------------------------------------------

DEFAULT_CONFIG.update({
    "max_graph_dependencies": 160,
    "max_graph_native_artifacts": 80,
    "max_graph_library_nodes": 180,
    "graph_propagation_depth": 4,
})

_collect_snapshot_v4 = collect_snapshot
_report_html_v4 = report_html
_make_report_v4 = make_report


def _node_id(kind: str, name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_.:/@+\\-]+", "_", str(name).strip())
    return f"{kind}:{clean}"[:300]


def _add_graph_node(nodes: Dict[str, dict], kind: str, name: str, label: Optional[str] = None,
                    state: Any = None, metadata: Optional[dict] = None) -> str:
    nid = _node_id(kind, name)
    rec = nodes.setdefault(nid, {
        "id": nid, "kind": kind, "name": str(name), "label": label or str(name),
        "state": state, "metadata": metadata or {},
    })
    if rec.get("state") is None and state is not None:
        rec["state"] = state
    if metadata:
        rec.setdefault("metadata", {}).update(metadata)
    return nid


def _add_graph_edge(edges: List[dict], seen: set, src: str, dst: str, relation: str) -> None:
    if not src or not dst or src == dst:
        return
    key = (src, dst, relation)
    if key not in seen:
        seen.add(key)
        edges.append({"src": src, "dst": dst, "relation": relation})


def build_failure_graph(snapshot: dict) -> dict:
    """Build a bounded graph where src depends on dst.

    This graph intentionally describes engineering causality rather than source-code call graphs.
    It joins project families, packages, native artifacts/imports, SDKs, engines, tools, and hardware.
    """
    cfg = DEFAULT_CONFIG.copy()
    nodes: Dict[str, dict] = {}
    edges: List[dict] = []
    edge_seen = set()
    project = snapshot.get("project", {}) or {}
    families = list(project.get("families", []) or [])
    root = _add_graph_node(nodes, "project", "root", "project", state={
        "families": families,
        "files": len(snapshot.get("project_files", {}) or {}),
    })

    components: Dict[str, str] = {}
    for fam in families:
        cid = _add_graph_node(nodes, "component", fam, fam, state="present", metadata={"ecosystem": fam})
        components[fam] = cid
        _add_graph_edge(edges, edge_seen, root, cid, "contains")

    tools = snapshot.get("tools", {}) or {}
    tool_nodes = {}
    for name, info in sorted(tools.items()):
        if not info.get("present"):
            continue
        tid = _add_graph_node(nodes, "tool", name, name, state={
            "version": info.get("version"), "path": info.get("path")
        })
        tool_nodes[name] = tid

    family_tools = {
        "python": ("python",), "node": ("node", "npm"), "cpp": ("cmake", "cl", "gcc", "clang", "msbuild"),
        "rust": ("rustc", "cargo"), "go": ("go",), "dotnet": ("dotnet",),
        "android": ("java", "adb"), "cuda": ("nvcc",), "vulkan": ("vulkaninfo",), "docker": ("docker",),
    }
    for fam, names in family_tools.items():
        cid = components.get(fam)
        if not cid:
            continue
        for name in names:
            if name in tool_nodes:
                _add_graph_edge(edges, edge_seen, cid, tool_nodes[name], "uses-tool")

    if "unreal" in components and "cpp" in components:
        _add_graph_edge(edges, edge_seen, components["unreal"], components["cpp"], "requires")
    if "cuda" in components and "cpp" in components:
        _add_graph_edge(edges, edge_seen, components["cuda"], components["cpp"], "extends")
    if "vulkan" in components and "cpp" in components:
        _add_graph_edge(edges, edge_seen, components["vulkan"], components["cpp"], "extends")

    native = snapshot.get("native", {}) or {}
    graph = native.get("dependency_graph", {}) or {}
    dep_limit = int(cfg.get("max_graph_dependencies", 160))
    dep_count = 0
    eco_to_family = {"python": "python", "node": "node", "rust": "rust", "go": "go"}
    for eco, packages in sorted((graph.get("packages", {}) or {}).items()):
        cid = components.get(eco_to_family.get(eco, eco)) or root
        for pkg in packages:
            if dep_count >= dep_limit:
                break
            name = pkg.get("name") or "unknown"
            version = pkg.get("version")
            did = _add_graph_node(nodes, "dependency", f"{eco}/{name}", name,
                                  state=version, metadata={"ecosystem": eco, "version": version})
            _add_graph_edge(edges, edge_seen, cid, did, "depends-on")
            dep_count += 1
        if dep_count >= dep_limit:
            break

    sdks = native.get("sdks", {}) or {}
    sdk_map = {
        "cuda": ("cuda", "cuda"), "vulkan": ("vulkan", "vulkan"), "android": ("android", "android"),
        "java": ("java", "android"), "visual_studio_cpp": ("visual-studio-cpp", "cpp"),
        "dotnet_sdks": ("dotnet", "dotnet"),
    }
    for key, (label, fam) in sdk_map.items():
        value = sdks.get(key)
        if not value:
            continue
        sid = _add_graph_node(nodes, "sdk", label, label, state=_fingerprint(value), metadata={"inventory": value})
        if fam in components:
            _add_graph_edge(edges, edge_seen, components[fam], sid, "uses-sdk")

    engines = native.get("engines", {}) or {}
    for eng_name, installs in engines.items():
        if not installs:
            continue
        fam = "unreal" if "unreal" in eng_name.lower() else "unity" if "unity" in eng_name.lower() else eng_name.lower()
        for install in installs[:20]:
            ver = str(install.get("version") or install.get("path") or "unknown")
            eid = _add_graph_node(nodes, "engine", f"{fam}/{ver}", f"{fam} {ver}", state=install,
                                  metadata={"ecosystem": fam})
            if fam in components:
                _add_graph_edge(edges, edge_seen, components[fam], eid, "uses-engine")

    host = snapshot.get("host", {}) or {}
    gpu = host.get("gpu")
    gpu_node = None
    if gpu:
        gpu_node = _add_graph_node(nodes, "hardware", "gpu", str(gpu), state={
            "gpu": gpu, "driver_fingerprint": host.get("gpu_driver_fingerprint")
        })
        for fam in ("cuda", "vulkan", "unreal", "unity"):
            if fam in components:
                _add_graph_edge(edges, edge_seen, components[fam], gpu_node, "runs-on")
    cpu_node = _add_graph_node(nodes, "hardware", "cpu-architecture", host.get("machine") or "cpu",
                               state=host.get("machine"))
    _add_graph_edge(edges, edge_seen, root, cpu_node, "runs-on")

    art_limit = int(cfg.get("max_graph_native_artifacts", 80))
    lib_limit = int(cfg.get("max_graph_library_nodes", 180))
    lib_nodes = 0
    artifacts = (native.get("native_artifacts", {}) or {}).get("artifacts", []) or []
    native_component = components.get("cpp") or components.get("unreal") or root
    for art in artifacts[:art_limit]:
        path = art.get("path") or "binary"
        aid = _add_graph_node(nodes, "native-artifact", path, Path(path).name,
                              state=art.get("sha256"), metadata={"path": path, "size": art.get("size")})
        _add_graph_edge(edges, edge_seen, native_component, aid, "produces-or-loads")
        for dep in (art.get("dependencies") or []):
            if lib_nodes >= lib_limit:
                break
            # ldd/otool lines are retained as labels; PE imports are usually bare DLL names.
            lname = str(dep).strip()
            lid = _add_graph_node(nodes, "native-library", lname, lname, state=lname)
            _add_graph_edge(edges, edge_seen, aid, lid, "imports")
            lib_nodes += 1

    canonical_nodes = [
        f"{n['id']}|{_fingerprint(n.get('state'))}" for n in sorted(nodes.values(), key=lambda x: x["id"])
    ]
    canonical_edges = [f"{e['src']}|{e['relation']}|{e['dst']}" for e in sorted(edges, key=lambda x: (x['src'], x['relation'], x['dst']))]
    fp = hashlib.sha256("\n".join(canonical_nodes + canonical_edges).encode()).hexdigest()
    return {
        "schema": 1, "fingerprint": fp, "nodes": list(sorted(nodes.values(), key=lambda x: x["id"])),
        "edges": sorted(edges, key=lambda x: (x["src"], x["relation"], x["dst"])),
        "node_count": len(nodes), "edge_count": len(edges),
        "truncated": dep_count >= dep_limit or len(artifacts) > art_limit or lib_nodes >= lib_limit,
    }


def graph_delta(baseline_graph: dict, current_graph: dict) -> dict:
    bnodes = {n["id"]: n for n in baseline_graph.get("nodes", [])}
    cnodes = {n["id"]: n for n in current_graph.get("nodes", [])}
    added = sorted(set(cnodes) - set(bnodes))
    removed = sorted(set(bnodes) - set(cnodes))
    changed = []
    for nid in sorted(set(bnodes) & set(cnodes)):
        if _fingerprint(bnodes[nid].get("state")) != _fingerprint(cnodes[nid].get("state")):
            changed.append(nid)
    bedges = {(e["src"], e["relation"], e["dst"]) for e in baseline_graph.get("edges", [])}
    cedges = {(e["src"], e["relation"], e["dst"]) for e in current_graph.get("edges", [])}
    return {
        "fingerprint_changed": baseline_graph.get("fingerprint") != current_graph.get("fingerprint"),
        "added_nodes": added, "removed_nodes": removed, "changed_nodes": changed,
        "added_edges": len(cedges - bedges), "removed_edges": len(bedges - cedges),
    }


def collect_snapshot(root: Path) -> dict:
    snap = _collect_snapshot_v4(root)
    snap["schema"] = 5
    snap["app_version"] = APP_VERSION
    snap["failure_graph"] = build_failure_graph(snap)
    return snap


def _graph_maps(graph: dict) -> Tuple[Dict[str, dict], Dict[str, List[str]], Dict[str, List[str]]]:
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    forward: Dict[str, List[str]] = {nid: [] for nid in nodes}
    reverse: Dict[str, List[str]] = {nid: [] for nid in nodes}
    for e in graph.get("edges", []):
        if e.get("src") in nodes and e.get("dst") in nodes:
            forward[e["src"]].append(e["dst"])
            reverse[e["dst"]].append(e["src"])
    return nodes, forward, reverse


def graph_blast_radius(graph: dict, node_id: str, max_depth: int = 5) -> dict:
    nodes, _forward, reverse = _graph_maps(graph)
    if node_id not in nodes:
        return {"node": node_id, "affected": [], "count": 0}
    q = deque([(node_id, 0)])
    seen = {node_id}
    affected = []
    while q:
        cur, depth = q.popleft()
        if depth >= max_depth:
            continue
        for nxt in reverse.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            affected.append({"id": nxt, "depth": depth + 1, "kind": nodes[nxt].get("kind"), "label": nodes[nxt].get("label")})
            q.append((nxt, depth + 1))
    affected.sort(key=lambda x: (x["depth"], x["kind"], x["label"]))
    return {"node": node_id, "affected": affected, "count": len(affected)}


def _node_validation(node: dict, families: Sequence[str]) -> str:
    kind = node.get("kind")
    meta = node.get("metadata", {}) or {}
    eco = str(meta.get("ecosystem") or "").lower()
    name = str(node.get("name") or "").lower()
    if kind == "dependency":
        if eco == "python": return f'"{sys.executable}" -m pip check'
        if eco == "node": return "npm ls --depth=0"
        if eco == "rust": return "cargo check"
        if eco == "go": return "go test ./..."
    if kind in {"native-artifact", "native-library"}: return "cmake --build build --config Debug"
    if kind == "tool": return f"{name} --version" if name not in {"cl", "msbuild"} else ("cl" if name == "cl" else "msbuild -version")
    if kind == "sdk":
        if "cuda" in name: return "nvcc --version"
        if "vulkan" in name: return "vulkaninfo --summary"
        if "android" in name: return "adb version"
        if "dotnet" in name: return "dotnet --info"
    if kind == "engine":
        if "unreal" in name: return "Regenerate Unreal project files and compile the Editor target for the pinned engine"
        if "unity" in name: return "Open the project in the pinned Unity editor and run a batchmode compile/test pass"
    if kind == "hardware" and "gpu" in name: return "nvidia-smi (NVIDIA) or vendor driver diagnostics, then run the graphics API smoke test"
    if "cpp" in families: return "cmake --build build --config Debug"
    if "python" in families: return f'"{sys.executable}" -m pip check'
    return "driftguard doctor"


def failure_graph_prediction(root: Path, report: dict, baseline_graph: dict) -> dict:
    graph = report.get("current", {}).get("failure_graph", {}) or {}
    nodes, _forward, reverse = _graph_maps(graph)
    delta = graph_delta(baseline_graph or {}, graph)
    scores = {nid: 0.0 for nid in nodes}
    reasons: Dict[str, List[str]] = {nid: [] for nid in nodes}
    direct = set()

    def seed(nid: str, amount: float, reason: str) -> None:
        if nid not in scores: return
        if amount > scores[nid]: scores[nid] = min(100.0, amount)
        reasons[nid].append(reason)
        direct.add(nid)

    for nid in delta.get("changed_nodes", []): seed(nid, 48, "node state changed from baseline")
    for nid in delta.get("added_nodes", []): seed(nid, 32, "node appeared since baseline")

    # Removed nodes cannot be scored directly because they no longer exist. Seed surviving dependents.
    bnodes, _bfwd, brev = _graph_maps(baseline_graph or {})
    for removed in delta.get("removed_nodes", []):
        for dependent in brev.get(removed, []):
            if dependent in scores:
                seed(dependent, 58, f"required node disappeared: {removed}")

    category_kinds = {
        "dependencies": {"dependency"}, "native": {"native-artifact", "native-library", "component"},
        "hardware": {"hardware", "component"}, "toolchain": {"tool", "component"},
        "sdk": {"sdk", "component"}, "engine": {"engine", "component"},
        "environment": {"tool", "sdk", "component"}, "host": {"hardware", "component"},
        "project": set(),
    }
    sev_seed = {"critical": 78, "high": 62, "medium": 42, "low": 22, "info": 0}
    for f in report.get("findings", []):
        cat = str(f.get("category", "")).lower()
        item_text = " ".join(str(f.get(k, "")) for k in ("item", "message", "current")).lower()
        kinds = category_kinds.get(cat, set())
        candidates = []
        for nid, node in nodes.items():
            hay = (nid + " " + str(node.get("label", ""))).lower()
            keyword = any(tok and len(tok) >= 4 and tok in hay for tok in re.findall(r"[a-z0-9_.+-]+", item_text))
            if keyword or node.get("kind") in kinds:
                candidates.append((0 if keyword else 1, nid))
        for _, nid in sorted(candidates)[:8]:
            seed(nid, sev_seed.get(str(f.get("severity")), 35), f"{f.get('severity')}: {f.get('item')}")

    sig_affinity = {
        "python.module-missing": ({"dependency", "component"}, "python"),
        "python.syntax": ({"source-component", "component"}, "python"),
        "python.native-load": ({"native-artifact", "native-library", "tool", "component"}, "python"),
        "node.resolve": ({"dependency", "component"}, "node"),
        "node.syntax": ({"source-component", "component"}, "node"),
        "cmake.compiler": ({"tool", "component"}, "cpp"),
        "cmake.package": ({"dependency", "sdk", "component"}, "cpp"),
        "msvc.unresolved-symbol": ({"native-artifact", "native-library", "tool", "component"}, "cpp"),
        "msvc.runtime-mismatch": ({"native-artifact", "native-library", "tool", "component"}, "cpp"),
        "cpp.compile": ({"source-component", "component"}, "cpp"),
        "native.undefined-reference": ({"native-artifact", "native-library", "tool", "component"}, "cpp"),
        "native.architecture": ({"native-artifact", "hardware", "component"}, "cpp"),
        "cuda.driver-toolkit": ({"sdk", "hardware", "tool", "component"}, "cuda"),
        "vulkan.driver": ({"sdk", "hardware", "component"}, "vulkan"),
        "unreal.engine-version": ({"engine", "native-artifact", "component"}, "unreal"),
        "dotnet.sdk": ({"sdk", "tool", "component"}, "dotnet"),
        "go.syntax": ({"source-component", "component"}, "go"),
        "gradle.java": ({"sdk", "tool", "component"}, "android"),
        "docker.daemon": ({"tool", "component"}, "docker"),
    }
    for incident in load_recent_incidents(root, 40)[-20:]:
        sig = incident.get("primary_signature")
        kinds, eco = sig_affinity.get(sig, (set(), ""))
        if not kinds: continue
        for nid, node in nodes.items():
            neco = str((node.get("metadata") or {}).get("ecosystem") or node.get("name") or "").lower()
            if node.get("kind") in kinds and (not eco or eco in neco or node.get("kind") not in {"component", "dependency"}):
                seed(nid, 54, f"recent incident: {sig}")

    # Propagate risk from dependencies toward their dependents. The graph edge is dependent -> dependency,
    # so the reverse adjacency is what carries a dependency failure's blast radius upward.
    max_depth = int(DEFAULT_CONFIG.get("graph_propagation_depth", 4))
    q = deque((nid, scores[nid], 0, nid) for nid in direct if scores[nid] > 0)
    best_prop: Dict[Tuple[str, str], float] = {}
    while q:
        cur, value, depth, origin = q.popleft()
        if depth >= max_depth: continue
        next_value = value * 0.62
        if next_value < 8: continue
        for dependent in reverse.get(cur, []):
            key = (origin, dependent)
            if best_prop.get(key, 0) >= next_value: continue
            best_prop[key] = next_value
            if next_value > scores[dependent]:
                scores[dependent] = min(100.0, next_value)
            reasons[dependent].append(f"propagated from {nodes[origin].get('label')} ({int(next_value)})")
            q.append((dependent, next_value, depth + 1, origin))

    families = report.get("current", {}).get("project", {}).get("families", []) or []
    ranked = []
    for nid, score in scores.items():
        if nid == "project:root" or score <= 0: continue
        node = nodes[nid]
        blast = graph_blast_radius(graph, nid, max_depth=4)
        label = "LOW" if score < 25 else "GUARDED" if score < 50 else "ELEVATED" if score < 75 else "HIGH"
        ranked.append({
            "node_id": nid, "kind": node.get("kind"), "label": node.get("label"),
            "risk": int(round(score)), "risk_label": label, "direct": nid in direct,
            "reasons": list(dict.fromkeys(reasons[nid]))[:6], "blast_radius": blast.get("count", 0),
            "validation": _node_validation(node, families),
        })
    ranked.sort(key=lambda x: (-x["risk"], -x["blast_radius"], x["node_id"]))
    top = ranked[0] if ranked else None
    return {
        "graph_fingerprint": graph.get("fingerprint"), "delta": delta,
        "top_node": top, "ranked_nodes": ranked[:30],
        "next_validation": ({"node_id": top["node_id"], "command": top["validation"], "reason": top["reasons"][0] if top.get("reasons") else "highest graph risk"} if top else None),
    }


def make_report(root: Path) -> dict:
    baseline_path = state_path(root, BASELINE_FILE)
    if not baseline_path.exists(): raise FileNotFoundError("No baseline. Run: driftguard init")
    baseline = load_json(baseline_path)
    current = collect_snapshot(root)
    findings = compare(baseline, current)
    score_value = stability_score(findings)
    reqs = doctor(current)
    report = {
        "schema": 5, "generated_at": now_iso(), "project_root": str(root.resolve()),
        "baseline_timestamp": baseline.get("timestamp"), "score": score_value,
        "status": stability_status(score_value, findings),
        "counts": {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in findings], "requirements": [asdict(r) for r in reqs],
        "current": current,
        "recent_incidents": load_recent_incidents(root, int(get_config(root).get("incident_history_limit", 100)))[-8:],
    }
    report["prediction"] = predict_risk(root, report, reqs)
    baseline_graph = baseline.get("failure_graph") or build_failure_graph(baseline)
    report["failure_graph_prediction"] = failure_graph_prediction(root, report, baseline_graph)
    # Graph evidence can lift overall risk, but never suppress v4's evidence-based score.
    top = (report["failure_graph_prediction"].get("top_node") or {}).get("risk", 0)
    if top:
        lifted = max(report["prediction"].get("risk", 0), min(96, int(report["prediction"].get("risk", 0) * 0.72 + top * 0.40)))
        report["prediction"]["risk"] = lifted
        report["prediction"]["label"] = "LOW" if lifted < 25 else "GUARDED" if lifted < 50 else "ELEVATED" if lifted < 75 else "HIGH"
        report["prediction"]["graph_top_node"] = report["failure_graph_prediction"].get("top_node")
    ensure_state(root); write_json(state_path(root, LAST_REPORT_FILE), report)
    append_jsonl(state_path(root, HISTORY_FILE), {
        "timestamp": report["generated_at"], "score": report["score"], "status": report["status"],
        "risk": report["prediction"]["risk"], "risk_label": report["prediction"]["label"],
        "counts": report["counts"], "graph_top": (report["failure_graph_prediction"].get("top_node") or {}).get("node_id"),
    })
    return report


def failure_graph_dot(graph: dict, prediction: Optional[dict] = None) -> str:
    pred_map = {x["node_id"]: x for x in (prediction or {}).get("ranked_nodes", [])}
    lines = ["digraph DriftGuard {", '  rankdir="LR";', '  graph [fontname="Arial"];', '  node [shape=box,fontname="Arial"];']
    for n in graph.get("nodes", []):
        p = pred_map.get(n["id"], {})
        suffix = f"\\nrisk={p.get('risk')}" if p else ""
        label = str(n.get("label") or n["id"]).replace('"', '\\"') + suffix
        shape = "ellipse" if n.get("kind") in {"dependency", "native-library"} else "box"
        lines.append(f'  "{n["id"]}" [label="{label}",shape={shape}];')
    for e in graph.get("edges", []):
        rel = str(e.get("relation", "")).replace('"', '\\"')
        lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{rel}"];')
    lines.append("}")
    return "\n".join(lines)


def cmd_graph(root: Path, fmt: str, output: Optional[Path]) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e: print(str(e), file=sys.stderr); return 2
    graph = report.get("current", {}).get("failure_graph", {})
    pred = report.get("failure_graph_prediction", {})
    if fmt == "json":
        text_out = json.dumps({"graph": graph, "prediction": pred}, indent=2)
    elif fmt == "dot":
        text_out = failure_graph_dot(graph, pred)
    else:
        print(f"Failure graph: {graph.get('node_count',0)} nodes, {graph.get('edge_count',0)} edges")
        d = pred.get("delta", {})
        print(f"Baseline delta: +{len(d.get('added_nodes',[]))} / -{len(d.get('removed_nodes',[]))} / ~{len(d.get('changed_nodes',[]))} nodes")
        for row in pred.get("ranked_nodes", [])[:15]:
            print(f"[{row['risk_label']:<8}] {row['risk']:>3}/100  {row['kind']:<16} {row['label']}  blast={row['blast_radius']}")
            if row.get("reasons"): print("           " + "; ".join(row["reasons"][:2]))
        nxt = pred.get("next_validation")
        if nxt: print(f"Next validation: {nxt['command']}")
        return 1 if (pred.get("top_node") or {}).get("risk", 0) >= 75 else 0
    if output:
        output.write_text(text_out, encoding="utf-8")
        print(f"Wrote {fmt.upper()} graph: {output.resolve()}")
    else:
        print(text_out)
    return 0


def cmd_explain(root: Path, node_query: str, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e: print(str(e), file=sys.stderr); return 2
    graph = report.get("current", {}).get("failure_graph", {})
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    q = node_query.lower()
    matches = [n for n in nodes.values() if n["id"].lower() == q or q in n["id"].lower() or q in str(n.get("label", "")).lower()]
    if not matches:
        print(f"No graph node matches: {node_query}", file=sys.stderr); return 2
    node = sorted(matches, key=lambda n: (0 if n["id"].lower() == q else 1, len(n["id"])))[0]
    pred = next((x for x in report.get("failure_graph_prediction", {}).get("ranked_nodes", []) if x["node_id"] == node["id"]), None)
    blast = graph_blast_radius(graph, node["id"], 5)
    data = {"node": node, "prediction": pred, "blast_radius": blast}
    if json_output: print(json.dumps(data, indent=2)); return 0
    print(f"Node: {node['id']} ({node.get('kind')})")
    print(f"State: {json.dumps(node.get('state'), default=str)[:500]}")
    if pred:
        print(f"Risk: {pred['risk']}/100 {pred['risk_label']}")
        for reason in pred.get("reasons", []): print(f"  reason: {reason}")
        print(f"Validate: {pred.get('validation')}")
    else:
        print("Risk: no active evidence")
    print(f"Blast radius: {blast['count']} dependent node(s)")
    for x in blast.get("affected", [])[:20]: print(f"  depth {x['depth']}: {x['kind']} {x['label']}")
    return 0


def cmd_validate_next(root: Path, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e: print(str(e), file=sys.stderr); return 2
    nxt = report.get("failure_graph_prediction", {}).get("next_validation")
    if json_output: print(json.dumps(nxt or {}, indent=2)); return 0
    if not nxt:
        print("No elevated graph node requires targeted validation. Run the normal project test/build suite.")
        return 0
    print(f"Node   : {nxt['node_id']}")
    print(f"Reason : {nxt['reason']}")
    print(f"Validate: {nxt['command']}")
    return 0


def report_html(root: Path, report: dict) -> str:
    base = _report_html_v4(root, report)
    fg = report.get("failure_graph_prediction", {})
    graph = report.get("current", {}).get("failure_graph", {})
    rows = []
    for x in fg.get("ranked_nodes", [])[:12]:
        rows.append("<tr>" +
            f"<td><code>{html.escape(x['node_id'])}</code></td>" +
            f"<td>{html.escape(x['kind'])}</td>" +
            f"<td>{x['risk']}/100</td>" +
            f"<td>{x['blast_radius']}</td>" +
            f"<td>{html.escape('; '.join(x.get('reasons',[])[:2]))}</td>" +
            f"<td><code>{html.escape(x.get('validation') or '')}</code></td></tr>")
    nxt = fg.get("next_validation") or {}
    section = f"""
<section style='margin-top:24px'>
<h2>Failure graph</h2>
<div class='cards'>
  <div class='card'>Nodes<b>{graph.get('node_count',0)}</b></div>
  <div class='card'>Edges<b>{graph.get('edge_count',0)}</b></div>
  <div class='card'>Changed nodes<b>{len((fg.get('delta') or {}).get('changed_nodes',[]))}</b></div>
  <div class='card'>Next validation<b style='font-size:13px'>{html.escape(str(nxt.get('command') or 'normal test suite'))}</b></div>
</div>
<table><thead><tr><th>Node</th><th>Kind</th><th>Risk</th><th>Blast</th><th>Evidence</th><th>Validate</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="6" class="ok">No active graph risk.</td></tr>'}</tbody></table>
</section>
"""
    return base.replace("</body>", section + "</body>")


# ---------------------------------------------------------------------------
# DriftGuard v6: source-change impact intelligence.
# ---------------------------------------------------------------------------

APP_VERSION = "6.1.0"

SOURCE_SUFFIX_FAMILY = {
    ".py": "python", ".pyi": "python",
    ".js": "node", ".jsx": "node", ".mjs": "node", ".cjs": "node",
    ".ts": "node", ".tsx": "node",
    ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".rs": "rust", ".go": "go", ".cs": "dotnet",
    ".java": "android", ".kt": "android", ".kts": "android",
    ".cu": "cuda", ".cuh": "cuda",
    ".vert": "vulkan", ".frag": "vulkan", ".glsl": "vulkan", ".comp": "vulkan",
    ".hlsl": "vulkan", ".fx": "vulkan",
}

_SOURCE_GRAPH_KINDS = {"source-component"}


def _source_family_for_path(rel: str, families: Sequence[str]) -> Optional[str]:
    low = rel.replace("\\", "/").lower()
    suffix = Path(low).suffix.lower()
    fam = SOURCE_SUFFIX_FAMILY.get(suffix)
    if "unreal" in families and (low.endswith(".build.cs") or low.endswith(".target.cs") or low.startswith("source/") or "/source/" in low):
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cs"}:
            return "unreal"
    if "unity" in families and low.startswith("assets/") and suffix == ".cs":
        return "unity"
    return fam


def _source_bucket(rel: str) -> str:
    parts = Path(rel.replace("\\", "/")).parts
    if len(parts) <= 1:
        return "."
    return str(parts[0]).replace("\\", "/")


def _read_small_text(path: Path, limit: int = 200000) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _source_validation(root: Path, family: str, bucket: str, sample_paths: Sequence[str]) -> str:
    if family == "python":
        pyproject = _read_small_text(root / "pyproject.toml").lower()
        has_pytest = any((root / name).exists() for name in ("pytest.ini", "conftest.py")) or "pytest" in pyproject
        if (root / "tests").is_dir():
            if has_pytest:
                return f'"{sys.executable}" -m pytest -q'
            return f'"{sys.executable}" -m unittest discover -s tests -v'
        target = bucket if bucket != "." else "."
        return f'"{sys.executable}" -m compileall -q -f "{target}"'
    if family == "node":
        try:
            pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
        except Exception:
            pkg = {}
        scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
        test_script = str(scripts.get("test", ""))
        if test_script and "no test specified" not in test_script.lower():
            return "npm test"
        if scripts.get("build"):
            return "npm run build"
        sample = next((p for p in sample_paths if Path(p).suffix.lower() in {".js", ".mjs", ".cjs"}), None)
        return f'node --check "{sample}"' if sample else "npm ls --depth=0"
    if family == "rust": return "cargo test"
    if family == "go": return "go test ./..."
    if family == "dotnet": return "dotnet test"
    if family == "android": return "gradlew test (gradlew.bat test on Windows; ./gradlew test on macOS/Linux)"
    if family in {"cpp", "cuda", "vulkan"}:
        if (root / "CMakeLists.txt").exists(): return "cmake --build build --config Debug"
        return "Run the project's native debug build and targeted tests for the changed source area"
    if family == "unreal": return "Compile the affected Unreal Editor target/module for the pinned engine, then run relevant automation tests"
    if family == "unity": return "Run a Unity batchmode compile/test pass for the affected assembly or scene tests"
    return "Run the narrowest project test/build covering the changed source area"


def scan_source_manifest(root: Path, max_depth: int = 8, max_files: int = 4000, max_hash_bytes: int = 8000000) -> dict:
    """Create a bounded deterministic source manifest and aggregate logical source components."""
    families = infer_project(
        root,
        discover_project_files(root, max_depth),
        scan_source_shape(root, max_depth, max_files),
    ).get("families", [])
    files: Dict[str, dict] = {}
    component_members: Dict[str, List[Tuple[str, str, int]]] = {}
    truncated = False
    seen = 0
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS)
        names = sorted(names)
        base_path = Path(base)
        try:
            depth = len(base_path.relative_to(root).parts)
        except ValueError:
            depth = 0
        if depth > max_depth:
            dirs[:] = []
            continue
        for name in names:
            rel_path = (base_path / name).relative_to(root)
            rel = str(rel_path).replace("\\", "/")
            family = _source_family_for_path(rel, families)
            if not family:
                continue
            seen += 1
            if seen > max_files:
                truncated = True
                break
            p = root / rel_path
            try:
                size = p.stat().st_size
                digest = sha256_file(p) if size <= max_hash_bytes else hashlib.sha256(f"oversize:{size}".encode()).hexdigest()
            except OSError:
                continue
            bucket = _source_bucket(rel)
            rec = {"sha256": digest, "size": size, "family": family, "bucket": bucket}
            files[rel] = rec
            key = f"{family}/{bucket}"
            component_members.setdefault(key, []).append((rel, digest, size))
        if truncated:
            break

    components: Dict[str, dict] = {}
    for key, members in sorted(component_members.items()):
        family, bucket = key.split("/", 1)
        canonical = "\n".join(f"{p}|{d}|{s}" for p, d, s in sorted(members))
        samples = [p for p, _d, _s in sorted(members)[:8]]
        components[key] = {
            "family": family,
            "bucket": bucket,
            "file_count": len(members),
            "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(),
            "sample_paths": samples,
            "validation": _source_validation(root, family, bucket, samples),
        }
    manifest_fp = hashlib.sha256("\n".join(
        f"{p}|{rec['sha256']}|{rec['size']}" for p, rec in sorted(files.items())
    ).encode()).hexdigest()
    return {
        "schema": 1,
        "fingerprint": manifest_fp,
        "file_count": len(files),
        "files": files,
        "components": components,
        "truncated": truncated,
        "limit": max_files,
    }


def source_change_delta(baseline: dict, current: dict) -> dict:
    bman = baseline.get("source_manifest") or {}
    cman = current.get("source_manifest") or {}
    if "files" not in bman:
        return {
            "baseline_available": False,
            "requires_rebaseline": True,
            "added": [], "removed": [], "changed": [], "changed_components": [],
            "total_changes": 0,
            "note": "The existing baseline predates source-impact tracking. Validate the current project, then run driftguard init --force to enable source-change comparison.",
        }
    bf = bman.get("files", {}) or {}
    cf = cman.get("files", {}) or {}
    added = sorted(set(cf) - set(bf))
    removed = sorted(set(bf) - set(cf))
    changed = sorted(p for p in set(bf) & set(cf) if bf[p].get("sha256") != cf[p].get("sha256"))
    affected = added + removed + changed
    components = set()
    for path in affected:
        rec = cf.get(path) or bf.get(path) or {}
        family = rec.get("family")
        bucket = rec.get("bucket")
        if family and bucket is not None:
            components.add(f"{family}/{bucket}")
    return {
        "baseline_available": True,
        "requires_rebaseline": False,
        "added": added, "removed": removed, "changed": changed,
        "changed_components": sorted(components),
        "total_changes": len(affected),
        "truncated": bool(bman.get("truncated") or cman.get("truncated")),
    }


def _recompute_graph_fingerprint(graph: dict) -> dict:
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    canonical_nodes = [f"{n['id']}|{_fingerprint(n.get('state'))}" for n in sorted(nodes, key=lambda x: x["id"])]
    canonical_edges = [f"{e['src']}|{e['relation']}|{e['dst']}" for e in sorted(edges, key=lambda x: (x['src'], x['relation'], x['dst']))]
    graph["fingerprint"] = hashlib.sha256("\n".join(canonical_nodes + canonical_edges).encode()).hexdigest()
    graph["node_count"] = len(nodes)
    graph["edge_count"] = len(edges)
    return graph


_build_failure_graph_v5 = build_failure_graph


def build_failure_graph(snapshot: dict) -> dict:
    graph = _build_failure_graph_v5(snapshot)
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = list(graph.get("edges", []))
    seen = {(e["src"], e["dst"], e["relation"]) for e in edges}
    families = set((snapshot.get("project", {}) or {}).get("families", []) or [])
    source = snapshot.get("source_manifest", {}) or {}
    max_nodes = int(DEFAULT_CONFIG.get("max_graph_source_components", 120))
    for key, rec in list(sorted((source.get("components", {}) or {}).items()))[:max_nodes]:
        family = str(rec.get("family") or "source")
        bucket = str(rec.get("bucket") or ".")
        sid = _add_graph_node(
            nodes, "source-component", key, f"{family} source · {bucket}",
            state=rec.get("fingerprint"),
            metadata={
                "ecosystem": family, "family": family, "bucket": bucket,
                "file_count": rec.get("file_count", 0),
                "sample_paths": rec.get("sample_paths", []),
                "validation": rec.get("validation"),
            },
        )
        parent = _node_id("component", family) if family in families and _node_id("component", family) in nodes else "project:root"
        _add_graph_edge(edges, seen, parent, sid, "contains-source")
    graph["nodes"] = list(sorted(nodes.values(), key=lambda x: x["id"]))
    graph["edges"] = sorted(edges, key=lambda x: (x["src"], x["relation"], x["dst"]))
    graph["schema"] = 2
    graph["truncated"] = bool(graph.get("truncated") or len((source.get("components") or {})) > max_nodes)
    return _recompute_graph_fingerprint(graph)


def collect_snapshot_v6_base(root: Path) -> dict:
    """Collect the v5 snapshot without triggering the v6 override."""
    return _collect_snapshot_v4(root)


def collect_snapshot(root: Path) -> dict:
    """v6 snapshot adds bounded source fingerprints before building the failure graph."""
    cfg = get_config(root)
    snap = collect_snapshot_v6_base(root)
    snap["schema"] = 6
    snap["app_version"] = APP_VERSION
    snap["source_manifest"] = scan_source_manifest(
        root,
        int(cfg.get("source_scan_depth", max(8, int(cfg.get("max_scan_depth", 5))))),
        int(cfg.get("max_source_manifest_files", 4000)),
        int(cfg.get("max_source_hash_bytes", 8000000)),
    )
    snap["failure_graph"] = build_failure_graph(snap)
    return snap


def _neutralize_missing_source_baseline(baseline_graph: dict, current_graph: dict) -> dict:
    """Avoid upgrade noise when a v5 baseline has no source manifest."""
    clone = json.loads(json.dumps(baseline_graph or {}))
    nodes = {n["id"]: n for n in clone.get("nodes", [])}
    edges = list(clone.get("edges", []))
    seen = {(e["src"], e["dst"], e["relation"]) for e in edges}
    source_ids = set()
    for n in current_graph.get("nodes", []):
        if n.get("kind") in _SOURCE_GRAPH_KINDS:
            nodes[n["id"]] = n
            source_ids.add(n["id"])
    for e in current_graph.get("edges", []):
        if e.get("src") in source_ids or e.get("dst") in source_ids:
            key = (e["src"], e["dst"], e["relation"])
            if key not in seen and e.get("src") in nodes and e.get("dst") in nodes:
                edges.append(e); seen.add(key)
    clone["nodes"] = list(sorted(nodes.values(), key=lambda x: x["id"]))
    clone["edges"] = sorted(edges, key=lambda x: (x["src"], x["relation"], x["dst"]))
    clone["schema"] = max(int(clone.get("schema", 1)), 2)
    return _recompute_graph_fingerprint(clone)


_node_validation_v5 = _node_validation


def _node_validation(node: dict, families: Sequence[str]) -> str:
    if node.get("kind") == "source-component":
        meta = node.get("metadata", {}) or {}
        if meta.get("validation"):
            return str(meta["validation"])
    return _node_validation_v5(node, families)


def make_report(root: Path) -> dict:
    baseline_path = state_path(root, BASELINE_FILE)
    if not baseline_path.exists(): raise FileNotFoundError("No baseline. Run: driftguard init")
    baseline = load_json(baseline_path)
    current = collect_snapshot(root)
    findings = compare(baseline, current)
    score_value = stability_score(findings)
    reqs = doctor(current)
    impact = source_change_delta(baseline, current)
    report = {
        "schema": 6, "generated_at": now_iso(), "project_root": str(root.resolve()),
        "baseline_timestamp": baseline.get("timestamp"), "score": score_value,
        "status": stability_status(score_value, findings),
        "counts": {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER},
        "findings": [asdict(f) for f in findings], "requirements": [asdict(r) for r in reqs],
        "current": current, "source_impact": impact,
        "recent_incidents": load_recent_incidents(root, int(get_config(root).get("incident_history_limit", 100)))[-8:],
    }
    report["prediction"] = predict_risk(root, report, reqs)
    baseline_graph = baseline.get("failure_graph") or build_failure_graph(baseline)
    if "files" not in (baseline.get("source_manifest") or {}):
        baseline_graph = _neutralize_missing_source_baseline(baseline_graph, current.get("failure_graph", {}))
    report["failure_graph_prediction"] = failure_graph_prediction(root, report, baseline_graph)
    report["validation_plan"] = build_validation_plan(report, int(get_config(root).get("validation_plan_limit", 5)))
    top = (report["failure_graph_prediction"].get("top_node") or {}).get("risk", 0)
    if top:
        lifted = max(report["prediction"].get("risk", 0), min(96, int(report["prediction"].get("risk", 0) * 0.72 + top * 0.40)))
        report["prediction"]["risk"] = lifted
        report["prediction"]["label"] = "LOW" if lifted < 25 else "GUARDED" if lifted < 50 else "ELEVATED" if lifted < 75 else "HIGH"
        report["prediction"]["graph_top_node"] = report["failure_graph_prediction"].get("top_node")
    if impact.get("baseline_available") and impact.get("total_changes"):
        report["prediction"].setdefault("drivers", []).append({
            "type": "source-impact", "severity": "medium", "item": f"{impact['total_changes']} source file change(s)",
            "detail": "Changed source components are connected to targeted validation recommendations; source edits are not treated as environment drift by themselves.",
        })
    ensure_state(root); write_json(state_path(root, LAST_REPORT_FILE), report)
    append_jsonl(state_path(root, HISTORY_FILE), {
        "timestamp": report["generated_at"], "score": report["score"], "status": report["status"],
        "risk": report["prediction"]["risk"], "risk_label": report["prediction"]["label"],
        "counts": report["counts"], "graph_top": (report["failure_graph_prediction"].get("top_node") or {}).get("node_id"),
        "source_changes": impact.get("total_changes", 0),
    })
    return report


def cmd_impact(root: Path, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e: print(str(e), file=sys.stderr); return 2
    impact = report.get("source_impact", {})
    if json_output:
        print(json.dumps(impact, indent=2)); return 0
    if not impact.get("baseline_available"):
        print(impact.get("note") or "Source-impact baseline is not available.")
        return 0
    print(f"Source changes: {impact.get('total_changes',0)}")
    print(f"  modified: {len(impact.get('changed',[]))}  added: {len(impact.get('added',[]))}  removed: {len(impact.get('removed',[]))}")
    if impact.get("changed_components"):
        print("Affected components: " + ", ".join(impact["changed_components"]))
    display = {"changed": "modified", "added": "added", "removed": "removed"}
    for label in ("changed", "added", "removed"):
        for path in impact.get(label, [])[:20]:
            print(f"  {display[label]}: {path}")
    nxt = report.get("failure_graph_prediction", {}).get("next_validation")
    if nxt:
        print(f"Next validation: {nxt.get('command')}")
    return 0


def cmd_validate_next(root: Path, json_output: bool) -> int:
    try: report = make_report(root)
    except FileNotFoundError as e: print(str(e), file=sys.stderr); return 2
    nxt = report.get("failure_graph_prediction", {}).get("next_validation")
    impact = report.get("source_impact", {})
    payload = dict(nxt or {})
    if payload and payload.get("node_id", "").startswith("source-component:"):
        payload["source_changes"] = {
            "changed": impact.get("changed", [])[:20], "added": impact.get("added", [])[:20], "removed": impact.get("removed", [])[:20]
        }
    if json_output: print(json.dumps(payload, indent=2)); return 0
    if not nxt:
        if not impact.get("baseline_available") and impact.get("requires_rebaseline"):
            print(impact.get("note"))
        else:
            print("No elevated graph node requires targeted validation. Run the normal project test/build suite.")
        return 0
    print(f"Node   : {nxt['node_id']}")
    print(f"Reason : {nxt['reason']}")
    if nxt.get("node_id", "").startswith("source-component:") and impact.get("total_changes"):
        changed = (impact.get("changed", []) + impact.get("added", []) + impact.get("removed", []))[:8]
        if changed:
            print("Changed: " + ", ".join(changed))
    print(f"Validate: {nxt['command']}")
    return 0


def build_validation_plan(report: dict, limit: int = 5) -> dict:
    """Return a bounded, deduplicated sequence of targeted validations.

    The failure graph can rank many risky nodes that collapse to the same practical
    validation command. A plan groups those nodes so engineers get broad coverage
    without repeatedly running equivalent checks.
    """
    bounded_limit = max(1, min(int(limit), 20))
    prediction = report.get("failure_graph_prediction", {}) or {}
    ranked = list(prediction.get("ranked_nodes", []) or [])
    grouped: Dict[str, dict] = {}

    for row in ranked:
        command = str(row.get("validation") or "").strip()
        if not command:
            continue
        key = re.sub(r"\s+", " ", command).strip()
        if not key:
            continue
        entry = grouped.get(key)
        node = {
            "node_id": row.get("node_id"),
            "kind": row.get("kind"),
            "label": row.get("label"),
            "risk": int(row.get("risk", 0) or 0),
            "risk_label": row.get("risk_label"),
            "direct": bool(row.get("direct")),
            "blast_radius": int(row.get("blast_radius", 0) or 0),
        }
        if entry is None:
            grouped[key] = {
                "command": command,
                "risk": node["risk"],
                "risk_label": row.get("risk_label"),
                "primary_node": row.get("node_id"),
                "primary_reason": (row.get("reasons") or ["highest graph risk"])[0],
                "direct": bool(row.get("direct")),
                "blast_radius": node["blast_radius"],
                "nodes": [node],
            }
        else:
            entry["nodes"].append(node)
            entry["direct"] = bool(entry.get("direct") or row.get("direct"))
            entry["blast_radius"] = max(int(entry.get("blast_radius", 0)), node["blast_radius"])
            if node["risk"] > int(entry.get("risk", 0)):
                entry["risk"] = node["risk"]
                entry["risk_label"] = row.get("risk_label")
                entry["primary_node"] = row.get("node_id")
                entry["primary_reason"] = (row.get("reasons") or ["highest graph risk"])[0]

    steps = list(grouped.values())
    steps.sort(key=lambda x: (
        -int(x.get("risk", 0)),
        -int(bool(x.get("direct"))),
        -int(x.get("blast_radius", 0)),
        str(x.get("command", "")),
    ))
    steps = steps[:bounded_limit]
    for index, step in enumerate(steps, 1):
        step["order"] = index
        step["covered_nodes"] = len(step.get("nodes", []))

    risky_with_validation = sum(1 for row in ranked if str(row.get("validation") or "").strip())
    covered_node_ids = {
        node.get("node_id")
        for step in steps
        for node in step.get("nodes", [])
        if node.get("node_id")
    }
    impact = report.get("source_impact", {}) or {}
    return {
        "schema": 1,
        "limit": bounded_limit,
        "step_count": len(steps),
        "steps": steps,
        "coverage": {
            "risky_nodes_with_validation": risky_with_validation,
            "covered_risky_nodes": len(covered_node_ids),
        },
        "source_changes": {
            "total": int(impact.get("total_changes", 0) or 0),
            "components": list(impact.get("changed_components", []) or [])[:40],
        },
        "fallback": None if steps else "Run the normal project test/build suite.",
    }


def cmd_validate_plan(root: Path, limit: int, json_output: bool) -> int:
    try:
        report = make_report(root)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    plan = build_validation_plan(report, limit)
    if json_output:
        print(json.dumps(plan, indent=2))
        return 0
    if not plan.get("steps"):
        print(plan.get("fallback") or "No targeted validation plan is required.")
        return 0
    print(f"Validation plan: {plan['step_count']} step(s)")
    source = plan.get("source_changes", {})
    if source.get("total"):
        print(f"Source changes: {source['total']} across {len(source.get('components', []))} component(s)")
    for step in plan["steps"]:
        print(f"{step['order']}. [{step.get('risk_label') or 'RISK'} {step.get('risk', 0)}/100] {step['command']}")
        print(f"   Covers {step.get('covered_nodes', 0)} risky node(s); primary: {step.get('primary_node')}")
        if step.get("primary_reason"):
            print(f"   Reason: {step['primary_reason']}")
    return 1 if any(int(step.get("risk", 0)) >= 75 for step in plan["steps"]) else 0


_SAFE_FIXED_VALIDATIONS = {
    "npm test", "npm run build", "npm ls --depth=0",
    "cargo test", "cargo check", "go test ./...",
    "dotnet test", "dotnet --info",
    "cmake --build build --config Debug",
    "nvcc --version", "vulkaninfo --summary", "adb version",
    "cl", "msbuild -version", "docker --version", "git --version",
}


def _safe_validation_path(value: str) -> bool:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/\\ -")
    return bool(value) and all(ch in allowed for ch in value)


def _portable_validation_command(command: str, shell: str) -> Optional[str]:
    """Return a conservative portable command or None for a manual validation."""
    command = " ".join(str(command or "").split())
    if not command or any(ch in command for ch in ("\n", "\r", chr(96), "$", ";", "|", "&", ">", "<")):
        return None
    if command in _SAFE_FIXED_VALIDATIONS:
        return command

    if " -m " in command:
        _python, tail = command.split(" -m ", 1)
        if tail in {"pytest -q", "unittest discover -s tests -v", "pip check"}:
            return f'& $Python -m {tail}' if shell == "powershell" else f'"$PYTHON_BIN" -m {tail}'
        prefix = 'compileall -q -f "'
        if tail.startswith(prefix) and tail.endswith('"'):
            target = tail[len(prefix):-1]
            if not _safe_validation_path(target):
                return None
            if shell == "powershell":
                return f"& $Python -m compileall -q -f '{target}'"
            return f'"$PYTHON_BIN" -m compileall -q -f \'{target}\''

    node_prefix = 'node --check "'
    if command.startswith(node_prefix) and command.endswith('"'):
        target = command[len(node_prefix):-1]
        if not _safe_validation_path(target):
            return None
        return f"node --check '{target}'"

    return None


def render_validation_script(plan: dict, shell: str) -> str:
    shell = str(shell or "").lower()
    if shell not in {"bash", "powershell"}:
        raise ValueError("shell must be bash or powershell")
    steps = list(plan.get("steps", []) or [])

    if shell == "bash":
        lines = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            'PYTHON_BIN="' + "$" + '{PYTHON:-python3}"',
            "",
            "# Generated by DriftGuard. Review before execution.",
        ]
        for step in steps:
            command = str(step.get("command") or "")
            portable = _portable_validation_command(command, shell)
            label = f"{step.get('order', '?')}. {step.get('primary_node') or 'validation'}"
            lines.extend(["", f"echo '==> {label}'"])
            if portable:
                lines.append(portable)
            else:
                safe = command.replace("\n", " ").replace("\r", " ")
                lines.append(f"# MANUAL: {safe}")
        if not steps:
            lines.extend(["", "# No targeted validation steps. Run the normal project test/build suite."])
        return "\n".join(lines) + "\n"

    lines = [
        '$ErrorActionPreference = "Stop"',
        '$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }',
        "",
        "# Generated by DriftGuard. Review before execution.",
    ]
    for step in steps:
        command = str(step.get("command") or "")
        portable = _portable_validation_command(command, shell)
        label = f"{step.get('order', '?')}. {step.get('primary_node') or 'validation'}"
        label_ps = label.replace("'", "''")
        lines.extend(["", f"Write-Host '==> {label_ps}'"])
        if portable:
            lines.append(portable)
            lines.append("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
        else:
            safe = command.replace("\n", " ").replace("\r", " ")
            lines.append(f"# MANUAL: {safe}")
    if not steps:
        lines.extend(["", "# No targeted validation steps. Run the normal project test/build suite."])
    return "\n".join(lines) + "\n"


def cmd_validation_script(root: Path, shell: str, output: Optional[Path], limit: int) -> int:
    try:
        report = make_report(root)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    plan = build_validation_plan(report, limit)
    script = render_validation_script(plan, shell)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(script, encoding="utf-8", newline="\n")
        print(f"Wrote {shell} validation script: {output.resolve()}")
    else:
        print(script, end="")
    return 0


_report_html_v5 = report_html


def report_html(root: Path, report: dict) -> str:
    base = _report_html_v5(root, report)
    impact = report.get("source_impact", {}) or {}
    if not impact.get("baseline_available"):
        detail = html.escape(impact.get("note") or "Source-impact baseline not available.")
        section = f"<section style='margin-top:24px'><h2>Source impact</h2><div class='panel muted'>{detail}</div></section>"
        return base.replace("</body>", section + "</body>")
    paths = []
    for kind in ("changed", "added", "removed"):
        for path in impact.get(kind, [])[:12]:
            paths.append(f"<tr><td>{html.escape(kind)}</td><td><code>{html.escape(path)}</code></td></tr>")
    section = f"""
<section style='margin-top:24px'>
<h2>Source impact</h2>
<div class='cards'>
  <div class='card'>Source changes<b>{impact.get('total_changes',0)}</b></div>
  <div class='card'>Changed components<b>{len(impact.get('changed_components',[]))}</b></div>
  <div class='card'>Manifest bounded<b>{'yes' if impact.get('truncated') else 'no'}</b></div>
</div>
<table><thead><tr><th>Change</th><th>Path</th></tr></thead><tbody>{''.join(paths) if paths else '<tr><td colspan="2" class="ok">No source changes since baseline.</td></tr>'}</tbody></table>
</section>
"""
    plan = report.get("validation_plan") or build_validation_plan(report, int(get_config(root).get("validation_plan_limit", 5)))
    plan_rows = []
    for step in plan.get("steps", []):
        plan_rows.append(
            "<tr>"
            f"<td>{step.get('order')}</td>"
            f"<td>{html.escape(str(step.get('risk_label') or ''))} {int(step.get('risk', 0))}/100</td>"
            f"<td><code>{html.escape(str(step.get('command') or ''))}</code></td>"
            f"<td>{int(step.get('covered_nodes', 0))}</td>"
            f"<td>{html.escape(str(step.get('primary_node') or ''))}</td>"
            "</tr>"
        )
    plan_section = f"""
<section style='margin-top:24px'>
<h2>Validation plan</h2>
<div class='cards'>
  <div class='card'>Targeted steps<b>{plan.get('step_count',0)}</b></div>
  <div class='card'>Risk nodes covered<b>{(plan.get('coverage') or {}).get('covered_risky_nodes',0)}</b></div>
  <div class='card'>Risk nodes available<b>{(plan.get('coverage') or {}).get('risky_nodes_with_validation',0)}</b></div>
</div>
<table><thead><tr><th>#</th><th>Risk</th><th>Validation</th><th>Nodes</th><th>Primary node</th></tr></thead>
<tbody>{''.join(plan_rows) if plan_rows else '<tr><td colspan="5" class="ok">No targeted validation required; run the normal project suite.</td></tr>'}</tbody></table>
</section>
"""
    return base.replace("</body>", section + plan_section + "</body>")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="driftguard", description="Predictive environment drift, structural failure graphs, and build-failure diagnosis.")
    p.add_argument("--root", default=".", help="Project root (default: current directory)")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("init", help="Record a known-good baseline"); s.add_argument("--force", action="store_true")
    s = sub.add_parser("check", help="Full drift + risk report"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("predict", help="Predict build-failure risk"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("doctor", help="Check inferred project requirements"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("record", help="Record a successful/failed build or test outcome")
    s.add_argument("result", choices=["success", "failure"]); s.add_argument("--stage", default="build"); s.add_argument("--note", default="")
    s = sub.add_parser("guard", help="Preflight, run a command, then learn from the outcome")
    s.add_argument("--max-risk", type=int, default=None); s.add_argument("--force", action="store_true"); s.add_argument("--capture", action="store_true"); s.add_argument("cmd", nargs=argparse.REMAINDER)
    s = sub.add_parser("analyze-log", help="Classify an existing build/runtime log")
    s.add_argument("log_file"); s.add_argument("--json", action="store_true"); s.add_argument("--save", action="store_true")
    s = sub.add_parser("incidents", help="Show recent classified build incidents")
    s.add_argument("--limit", type=int, default=10); s.add_argument("--json", action="store_true")
    s = sub.add_parser("inventory", help="Show SDK, engine, GPU-driver, dependency-graph, and native-artifact inventory"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("subsystems", help="Rank likely failure subsystems and targeted validations"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("native-scan", help="Inspect native binaries and imported shared-library dependencies"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("graph", help="Show/export the structural failure graph")
    s.add_argument("--format", choices=["text","json","dot"], default="text"); s.add_argument("-o", "--output")
    s = sub.add_parser("explain", help="Explain one graph node, its risk evidence, and blast radius")
    s.add_argument("node"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("validate-next", help="Show the highest-value validation to run next"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("validate-plan", help="Build a deduplicated, risk-prioritized validation sequence"); s.add_argument("--limit", type=int, default=5); s.add_argument("--json", action="store_true")
    s = sub.add_parser("validation-script", help="Export the targeted validation plan as a reviewable shell script"); s.add_argument("--shell", choices=["bash","powershell"], required=True); s.add_argument("--limit", type=int, default=5); s.add_argument("-o", "--output")
    s = sub.add_parser("impact", help="Show source files/components changed since the known-good baseline"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("export", help="Export standalone HTML dashboard"); s.add_argument("-o", "--output", default="driftguard-report.html")
    s = sub.add_parser("watch", help="Continuously detect changes"); s.add_argument("--interval", type=int, default=None)
    s = sub.add_parser("serve", help="Run local dashboard"); s.add_argument("--port", type=int, default=8765)
    return p


def main() -> int:
    args = build_parser().parse_args()
    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"Invalid project root: {root}", file=sys.stderr); return 2
    if args.command == "init": return cmd_init(root, args.force)
    if args.command == "check": return cmd_check(root, args.json)
    if args.command == "predict": return cmd_predict(root, args.json)
    if args.command == "doctor": return cmd_doctor(root, args.json)
    if args.command == "record": return cmd_record(root, args.result, args.stage, args.note)
    if args.command == "guard": return cmd_guard(root, args.cmd, args.max_risk, args.force, args.capture)
    if args.command == "analyze-log": return cmd_analyze_log(root, Path(args.log_file), args.json, args.save)
    if args.command == "incidents": return cmd_incidents(root, max(1, args.limit), args.json)
    if args.command == "inventory": return cmd_inventory(root, args.json)
    if args.command == "subsystems": return cmd_subsystems(root, args.json)
    if args.command == "native-scan": return cmd_native_scan(root, args.json)
    if args.command == "graph": return cmd_graph(root, args.format, Path(args.output) if args.output else None)
    if args.command == "explain": return cmd_explain(root, args.node, args.json)
    if args.command == "validate-next": return cmd_validate_next(root, args.json)
    if args.command == "validate-plan": return cmd_validate_plan(root, max(1, args.limit), args.json)
    if args.command == "validation-script": return cmd_validation_script(root, args.shell, Path(args.output) if args.output else None, max(1, args.limit))
    if args.command == "impact": return cmd_impact(root, args.json)
    if args.command == "export": return cmd_export(root, Path(args.output))
    if args.command == "watch": return cmd_watch(root, max(1, args.interval or int(get_config(root).get("watch_interval", 10))))
    if args.command == "serve": return cmd_serve(root, args.port)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
