#!/usr/bin/env python3
"""
DriftGuard 5
Project-aware environment drift + build-failure prediction + log intelligence.

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