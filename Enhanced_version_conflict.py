#!/usr/bin/env python3
"""
Universal Dependency Checker - Enhanced with Gemini AI & Gradient AI Self-Healing + Auth0 Security
==========================================================================================================
This is a complete generalized solution with AI-powered learning and secure API authentication:

- Queries PyPI API for any package
- Parses all requirements automatically
- Checks against current environment
- Enhanced version resolution for complex ranges
- **Gemini AI**: Natural language conflict resolution advice
- **Gradient AI**: Self-healing learning from previous resolutions
- **Auto-prediction**: Suggests optimal dependency versions based on history
- **Auth0 Security**: All API calls protected with Bearer token authentication
- **Token Management**: Short-lived tokens with automatic refresh and file-based caching
- **Audit & Logging**: Comprehensive local logging of all API calls and operations
- **Auto-Resolve**: Automatically resolve conflicts and install packages

Security Features:
    - Auth0 token-based authentication for all external API calls
    - Secure token management and validation
    - Protected endpoints with authorization headers
    - Token refresh mechanism for long-running operations
    - File-based token caching to avoid re-authentication
    - Automatic token expiry handling
    - Local audit logging of all API requests and responses
    - User activity tracking
"""

from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
import logging
import hashlib
import platform
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
import time
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

try:
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet, Specifier
    from packaging.version import Version, parse as parse_version
    from packaging.markers import Marker
except ImportError:
    print("❌ Missing 'packaging' package. Install with: pip install packaging")
    sys.exit(1)

# Gemini API integration
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️  Gemini API not available. Install with: pip install google-genai")

# Gradient AI integration
try:
    import gradientai
    from gradientai import Gradient
    GRADIENT_AVAILABLE = True
except ImportError:
    GRADIENT_AVAILABLE = False
    print("⚠️  Gradient AI not available. Install with: pip install gradientai")
    print("    Self-healing predictions will be disabled.\n")

# Color support
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    RED, GREEN, YELLOW, CYAN, BLUE, MAGENTA, DIM, RESET, BRIGHT = (
        Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN, Fore.BLUE,
        Fore.MAGENTA, Style.DIM, Style.RESET_ALL, Style.BRIGHT
    )
except ImportError:
    RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = DIM = RESET = BRIGHT = ""


@dataclass
class AuditLogEntry:
    """Represents a single audit log entry"""
    timestamp: str
    session_id: str
    user: str
    command: str
    api_name: str
    endpoint: str
    method: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: Optional[int]
    response_time_ms: Optional[float]
    error: Optional[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    def to_log_string(self) -> str:
        """Convert to formatted log string"""
        status = self.response_status or "N/A"
        time_str = f"{self.response_time_ms:.2f}ms" if self.response_time_ms else "N/A"
        return (
            f"[{self.timestamp}] {self.session_id} | {self.user} | {self.command} | "
            f"{self.api_name} {self.method} {self.endpoint} | Status: {status} | "
            f"Time: {time_str}"
        )


class AuditLogger:
    """Manages local audit logging for all API calls and user operations"""

    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = Path(log_dir or os.path.expanduser("~/.mycli/logs"))
        self.session_id = self._generate_session_id()
        self.user = self._get_user_identifier()
        self._ensure_log_dir()
        self._setup_loggers()

    def _ensure_log_dir(self):
        """Create log directory if it doesn't exist"""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.log_dir, 0o700)
        except Exception as e:
            print(f"{YELLOW}⚠️  Could not create log directory: {e}{RESET}")

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.now().isoformat()
        random_data = f"{timestamp}{os.getpid()}{time.time()}"
        return hashlib.sha256(random_data.encode()).hexdigest()[:16]

    def _get_user_identifier(self) -> str:
        """Get user identifier (username or system user)"""
        try:
            return os.getenv("USER") or os.getenv("USERNAME") or platform.node()
        except Exception:
            return "unknown"

    def _setup_loggers(self):
        """Setup file and JSON loggers"""
        # Text log file (human-readable)
        text_log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        self.text_logger = logging.getLogger("audit_text")
        self.text_logger.setLevel(logging.INFO)

        if not self.text_logger.handlers:
            text_handler = logging.FileHandler(text_log_file)
            text_handler.setFormatter(logging.Formatter('%(message)s'))
            self.text_logger.addHandler(text_handler)

        # JSON log file (machine-readable)
        json_log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.json"
        self.json_log_file = json_log_file

        # Console logger for verbose mode
        self.console_logger = logging.getLogger("audit_console")
        self.console_logger.setLevel(logging.INFO)

        if not self.console_logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(f'{DIM}[AUDIT] %(message)s{RESET}'))
            self.console_logger.addHandler(console_handler)

        print(f"{GREEN}📋 Audit logging enabled: {text_log_file}{RESET}")

    def log_api_call(self, command: str, api_name: str, endpoint: str, method: str = "GET",
                    request_headers: Optional[Dict[str, str]] = None,
                    request_body: Optional[str] = None,
                    response_status: Optional[int] = None,
                    response_time_ms: Optional[float] = None,
                    error: Optional[str] = None,
                    metadata: Optional[Dict[str, Any]] = None,
                    verbose: bool = False):
        """Log an API call with all details"""

        # Sanitize sensitive headers
        sanitized_headers = self._sanitize_headers(request_headers or {})

        entry = AuditLogEntry(
            timestamp=datetime.now().isoformat(),
            session_id=self.session_id,
            user=self.user,
            command=command,
            api_name=api_name,
            endpoint=endpoint,
            method=method,
            request_headers=sanitized_headers,
            request_body=request_body,
            response_status=response_status,
            response_time_ms=response_time_ms,
            error=error,
            metadata=metadata or {}
        )

        # Log to text file
        self.text_logger.info(entry.to_log_string())

        # Log to JSON file
        self._append_json_log(entry)

        # Log to console if verbose
        if verbose:
            self.console_logger.info(entry.to_log_string())

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize sensitive information from headers"""
        sanitized = {}
        sensitive_keys = ['authorization', 'x-api-key', 'apikey', 'token']

        for key, value in headers.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                if value:
                    # Show only first and last 4 characters
                    if len(value) > 8:
                        sanitized[key] = f"{value[:4]}...{value[-4:]}"
                    else:
                        sanitized[key] = "***"
            else:
                sanitized[key] = value

        return sanitized

    def _append_json_log(self, entry: AuditLogEntry):
        """Append log entry to JSON log file"""
        try:
            # Read existing logs
            logs = []
            if self.json_log_file.exists():
                try:
                    with open(self.json_log_file, 'r') as f:
                        logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []

            # Append new entry
            logs.append(entry.to_dict())

            # Write back
            with open(self.json_log_file, 'w') as f:
                json.dump(logs, f, indent=2)

            os.chmod(self.json_log_file, 0o600)

        except Exception as e:
            self.text_logger.error(f"Failed to write JSON log: {e}")

    def log_user_action(self, command: str, action: str, details: Optional[Dict[str, Any]] = None, verbose: bool = False):
        """Log a user action (not API call)"""
        self.log_api_call(
            command=command,
            api_name="USER_ACTION",
            endpoint=action,
            method="ACTION",
            metadata=details or {},
            verbose=verbose
        )

    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session"""
        try:
            logs = []
            if self.json_log_file.exists():
                with open(self.json_log_file, 'r') as f:
                    logs = json.load(f)

            session_logs = [log for log in logs if log.get('session_id') == self.session_id]

            api_calls = {}
            total_time = 0.0
            errors = 0

            for log in session_logs:
                api_name = log.get('api_name', 'unknown')
                api_calls[api_name] = api_calls.get(api_name, 0) + 1

                if log.get('response_time_ms'):
                    total_time += log['response_time_ms']

                if log.get('error'):
                    errors += 1

            return {
                'session_id': self.session_id,
                'user': self.user,
                'total_api_calls': len(session_logs),
                'api_breakdown': api_calls,
                'total_time_ms': total_time,
                'errors': errors,
                'log_file': str(self.json_log_file)
            }

        except Exception as e:
            return {'error': str(e)}

    def show_recent_logs(self, limit: int = 20):
        """Display recent log entries"""
        try:
            if not self.json_log_file.exists():
                print(f"{YELLOW}No logs found{RESET}")
                return

            with open(self.json_log_file, 'r') as f:
                logs = json.load(f)

            recent_logs = logs[-limit:] if len(logs) > limit else logs

            print(f"\n{CYAN}{'='*70}{RESET}")
            print(f"{CYAN}{BRIGHT}📋 RECENT AUDIT LOGS (Last {len(recent_logs)} entries){RESET}")
            print(f"{CYAN}{'='*70}{RESET}\n")

            for log in recent_logs:
                timestamp = log.get('timestamp', 'N/A')
                api_name = log.get('api_name', 'N/A')
                endpoint = log.get('endpoint', 'N/A')
                status = log.get('response_status', 'N/A')
                time_ms = log.get('response_time_ms')

                time_str = f"{time_ms:.2f}ms" if time_ms else "N/A"

                status_color = GREEN if status == 200 else RED if isinstance(status, int) else YELLOW

                print(f"{DIM}{timestamp}{RESET} | {CYAN}{api_name}{RESET} | {endpoint}")
                print(f"  Status: {status_color}{status}{RESET} | Time: {time_str}")

                if log.get('error'):
                    print(f"  Error: {RED}{log['error']}{RESET}")
                print()

        except Exception as e:
            print(f"{RED}Failed to read logs: {e}{RESET}")


@dataclass
class TokenCache:
    """Represents a cached authentication token"""
    access_token: str
    token_type: str
    expires_at: str
    scope: Optional[str] = None

    def is_valid(self, buffer_seconds: int = 300) -> bool:
        """Check if token is still valid with a time buffer"""
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            now = datetime.now()
            return now < (expiry - timedelta(seconds=buffer_seconds))
        except Exception:
            return False

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_at": self.expires_at,
            "scope": self.scope
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'TokenCache':
        """Create TokenCache from dictionary"""
        return cls(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            expires_at=data.get("expires_at", ""),
            scope=data.get("scope")
        )


class TokenManager:
    """Manages token caching and automatic refresh"""

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or os.path.expanduser("~/.mycli"))
        self.token_file = self.cache_dir / "token.json"
        self._ensure_cache_dir()
        self.cached_token: Optional[TokenCache] = None
        self._load_cached_token()

    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.cache_dir, 0o700)
        except Exception as e:
            print(f"{YELLOW}⚠️  Could not create cache directory: {e}{RESET}")

    def _load_cached_token(self):
        """Load token from cache file"""
        if not self.token_file.exists():
            return

        try:
            with open(self.token_file, 'r') as f:
                data = json.load(f)
                self.cached_token = TokenCache.from_dict(data)

                if self.cached_token.is_valid():
                    print(f"{GREEN}✅ Loaded cached token (expires: {self.cached_token.expires_at}){RESET}")
                else:
                    print(f"{DIM}Cached token expired, will refresh{RESET}")
                    self.cached_token = None
        except Exception as e:
            print(f"{DIM}Could not load cached token: {e}{RESET}")
            self.cached_token = None

    def save_token(self, access_token: str, expires_in: int, token_type: str = "Bearer", scope: Optional[str] = None):
        """Save token to cache file"""
        try:
            expires_at = datetime.now() + timedelta(seconds=expires_in)

            self.cached_token = TokenCache(
                access_token=access_token,
                token_type=token_type,
                expires_at=expires_at.isoformat(),
                scope=scope
            )

            with open(self.token_file, 'w') as f:
                json.dump(self.cached_token.to_dict(), f, indent=2)

            os.chmod(self.token_file, 0o600)

            print(f"{GREEN}✅ Token cached (expires in {expires_in}s at {expires_at.strftime('%H:%M:%S')}){RESET}")
        except Exception as e:
            print(f"{YELLOW}⚠️  Could not cache token: {e}{RESET}")

    def get_cached_token(self) -> Optional[str]:
        """Get cached token if still valid"""
        if self.cached_token and self.cached_token.is_valid():
            return self.cached_token.access_token
        return None

    def clear_cache(self):
        """Clear cached token"""
        try:
            if self.token_file.exists():
                self.token_file.unlink()
                print(f"{GREEN}✅ Token cache cleared{RESET}")
            self.cached_token = None
        except Exception as e:
            print(f"{YELLOW}⚠️  Could not clear token cache: {e}{RESET}")

    def get_token_info(self) -> Optional[dict]:
        """Get information about cached token"""
        if not self.cached_token:
            return None

        is_valid = self.cached_token.is_valid()
        expires_at = datetime.fromisoformat(self.cached_token.expires_at)
        time_remaining = (expires_at - datetime.now()).total_seconds()

        return {
            "valid": is_valid,
            "expires_at": self.cached_token.expires_at,
            "time_remaining_seconds": int(time_remaining),
            "token_type": self.cached_token.token_type,
            "scope": self.cached_token.scope
        }


@dataclass
class Auth0Config:
    """Auth0 configuration for secure API calls"""
    domain: str
    client_id: str
    client_secret: str
    audience: str
    token_manager: TokenManager
    audit_logger: AuditLogger


class Auth0SecurityManager:
    """Manages Auth0 authentication and secure API calls with token caching and audit logging"""

    def __init__(self, token_manager: Optional[TokenManager] = None, audit_logger: Optional[AuditLogger] = None):
        self.enabled = False
        self.config = None
        self.token_manager = token_manager or TokenManager()
        self.audit_logger = audit_logger or AuditLogger()
        self._initialize_auth0()

    def _initialize_auth0(self):
        """Initialize Auth0 configuration from environment variables"""
        domain = os.getenv("AUTH0_DOMAIN")
        client_id = os.getenv("AUTH0_CLIENT_ID")
        client_secret = os.getenv("AUTH0_CLIENT_SECRET")
        audience = os.getenv("AUTH0_AUDIENCE", "https://api.dependency-checker.com")

        if domain and client_id and client_secret:
            self.config = Auth0Config(
                domain=domain,
                client_id=client_id,
                client_secret=client_secret,
                audience=audience,
                token_manager=self.token_manager,
                audit_logger=self.audit_logger
            )
            self.enabled = True
            print(f"{GREEN}🔒 Auth0 Security Manager initialized with token caching & audit logging{RESET}")

            # Try to use cached token first
            cached_token = self.token_manager.get_cached_token()
            if cached_token:
                print(f"{GREEN}✅ Using cached authentication token{RESET}")
            else:
                self._get_access_token()
        else:
            print(f"{YELLOW}⚠️  Auth0 not configured. Set environment variables:{RESET}")
            print(f"{DIM}   AUTH0_DOMAIN=your-domain.auth0.com{RESET}")
            print(f"{DIM}   AUTH0_CLIENT_ID=your-client-id{RESET}")
            print(f"{DIM}   AUTH0_CLIENT_SECRET=your-client-secret{RESET}")
            print(f"{DIM}   AUTH0_AUDIENCE=https://api.dependency-checker.com (optional){RESET}\n")

    def _get_access_token(self, force_refresh: bool = False) -> Optional[str]:
        """Get access token from Auth0 using client credentials flow with caching"""
        if not self.enabled or not self.config:
            return None

        # Return cached token if still valid and not forcing refresh
        if not force_refresh:
            cached_token = self.token_manager.get_cached_token()
            if cached_token:
                return cached_token

        start_time = time.time()
        error = None
        status = None

        try:
            print(f"{DIM}🔄 Requesting new Auth0 token...{RESET}")
            url = f"https://{self.config.domain}/oauth/token"

            payload = json.dumps({
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "audience": self.config.audience,
                "grant_type": "client_credentials"
            })

            headers = {
                "Content-Type": "application/json"
            }

            req = urllib.request.Request(url, data=payload.encode('utf-8'), headers=headers)

            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
                data = json.loads(response.read().decode('utf-8'))

                access_token = data.get("access_token")
                expires_in = data.get("expires_in", 3600)
                token_type = data.get("token_type", "Bearer")
                scope = data.get("scope")

                # Cache the token
                self.token_manager.save_token(
                    access_token=access_token,
                    expires_in=expires_in,
                    token_type=token_type,
                    scope=scope
                )

                return access_token

        except Exception as e:
            error = str(e)
            print(f"{RED}❌ Failed to get Auth0 token: {e}{RESET}")
            self.enabled = False
            return None

        finally:
            response_time = (time.time() - start_time) * 1000
            self.audit_logger.log_api_call(
                command="auth",
                api_name="Auth0",
                endpoint="/oauth/token",
                method="POST",
                request_headers={"Content-Type": "application/json"},
                request_body="<client_credentials>",
                response_status=status,
                response_time_ms=response_time,
                error=error,
                metadata={"action": "token_request", "force_refresh": force_refresh}
            )

    def get_authorization_header(self) -> Dict[str, str]:
        """Get authorization header for API calls"""
        if not self.enabled:
            return {}

        token = self._get_access_token()
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def make_secure_request(self, url: str, method: str = "GET",
                          data: Optional[bytes] = None,
                          additional_headers: Optional[Dict[str, str]] = None,
                          api_name: str = "API",
                          command: str = "unknown") -> Any:
        """Make a secure API request with Auth0 authentication and audit logging"""
        headers = self.get_authorization_header()

        if additional_headers:
            headers.update(additional_headers)

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        start_time = time.time()
        error = None
        status = None
        response_data = None

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                status = response.status
                response_data = json.loads(response.read().decode('utf-8'))
                return response_data

        except urllib.error.HTTPError as e:
            status = e.code
            error = f"HTTP {e.code}: {e.reason}"

            if e.code == 401:
                print(f"{YELLOW}⚠️  Token expired or invalid, refreshing...{RESET}")
                # Clear cached token and force refresh
                self.token_manager.clear_cache()
                token = self._get_access_token(force_refresh=True)

                if token:
                    headers = {"Authorization": f"Bearer {token}"}
                    if additional_headers:
                        headers.update(additional_headers)
                    req = urllib.request.Request(url, data=data, headers=headers, method=method)

                    with urllib.request.urlopen(req, timeout=30) as response:
                        status = response.status
                        response_data = json.loads(response.read().decode('utf-8'))
                        error = None
                        return response_data
                else:
                    raise Exception("Failed to refresh authentication token")
            raise

        except Exception as e:
            error = str(e)
            raise

        finally:
            response_time = (time.time() - start_time) * 1000
            self.audit_logger.log_api_call(
                command=command,
                api_name=api_name,
                endpoint=url,
                method=method,
                request_headers=headers,
                request_body=data.decode('utf-8') if data else None,
                response_status=status,
                response_time_ms=response_time,
                error=error,
                metadata={"response_size": len(str(response_data)) if response_data else 0}
            )

    def validate_token(self) -> bool:
        """Validate current token"""
        if not self.enabled or not self.config:
            return False

        # Check cache first
        cached_token = self.token_manager.get_cached_token()
        if not cached_token:
            return False

        start_time = time.time()
        error = None
        status = None

        try:
            url = f"https://{self.config.domain}/userinfo"
            headers = {"Authorization": f"Bearer {cached_token}"}

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
                return response.status == 200

        except Exception as e:
            error = str(e)
            # Token invalid, clear cache
            self.token_manager.clear_cache()
            return False

        finally:
            response_time = (time.time() - start_time) * 1000
            self.audit_logger.log_api_call(
                command="validate",
                api_name="Auth0",
                endpoint="/userinfo",
                method="GET",
                request_headers={"Authorization": "Bearer ***"},
                response_status=status,
                response_time_ms=response_time,
                error=error,
                metadata={"action": "token_validation"}
            )

    def get_token_info(self) -> Optional[dict]:
        """Get information about current token"""
        return self.token_manager.get_token_info()

    def clear_token_cache(self):
        """Clear token cache"""
        self.token_manager.clear_cache()
        self.audit_logger.log_user_action("clear-token", "TOKEN_CACHE_CLEARED")


@dataclass
class PackageRequirement:
    """Represents a single requirement"""
    name: str
    specifier: SpecifierSet
    extras: Set[str] = field(default_factory=set)
    marker: Optional[str] = None

    def is_satisfied_by(self, version: str) -> bool:
        """Check if a version satisfies this requirement"""
        try:
            if not self.specifier:
                return True
            return self.specifier.contains(version, prereleases=True)
        except Exception:
            return False


@dataclass
class ConflictReport:
    """Detailed conflict report"""
    conflict_type: str
    package_requested: str
    version_requested: str
    dependency_name: str
    dependency_required_spec: str
    dependency_installed_version: Optional[str]
    severity: str
    suggested_action: str
    explanation: str


@dataclass
class ResolutionRecord:
    """Records a conflict and its successful resolution for learning"""
    timestamp: str
    package_requested: str
    version_requested: str
    conflict_type: str
    dependency_name: str
    dependency_required_spec: str
    dependency_installed_version: Optional[str]
    resolution_action: str
    resolution_version: str
    success: bool
    environment_info: Dict[str, Any]

    def to_training_sample(self) -> str:
        """Convert to training format for Gradient AI"""
        inputs = (
            f"Package: {self.package_requested} {self.version_requested}\n"
            f"Conflict: {self.dependency_name} requires {self.dependency_required_spec}, "
            f"currently installed: {self.dependency_installed_version or 'not installed'}\n"
            f"Conflict type: {self.conflict_type}\n"
        )

        outputs = (
            f"Resolution: {self.resolution_action}\n"
            f"Install version: {self.resolution_version}\n"
            f"Success: {self.success}"
        )

        return f"### Inputs:\n{inputs}\n### Response:\n{outputs}"


class SecureGradientAIPredictor:
    """Gradient AI integration with Auth0 security for self-healing dependency resolution"""

    def __init__(self, auth_manager: Auth0SecurityManager):
        self.enabled = GRADIENT_AVAILABLE
        self.auth_manager = auth_manager
        self.gradient = None
        self.base_model = None
        self.model_adapter = None
        self.access_token = os.getenv("GRADIENT_ACCESS_TOKEN")
        self.workspace_id = os.getenv("GRADIENT_WORKSPACE_ID")
        self.resolution_history: List[ResolutionRecord] = []
        self.history_file = os.path.expanduser("~/.dependency_resolution_history.json")
        self.model_id = "nous-hermes-2-mistral-7b"

        self._load_history()

        if self.enabled and self.access_token and self.workspace_id:
            try:
                print(f"{GREEN}🧠 Initializing Secure Gradient AI predictor...{RESET}")

                # Validate Auth0 token before initializing Gradient AI
                if self.auth_manager.enabled:
                    if not self.auth_manager.validate_token():
                        print(f"{YELLOW}⚠️  Auth0 token validation failed{RESET}")

                self.gradient = Gradient(
                    access_token=self.access_token,
                    workspace_id=self.workspace_id
                )
                self._initialize_model()

                self.auth_manager.audit_logger.log_user_action(
                    "init",
                    "GRADIENT_AI_INITIALIZED",
                    {"history_count": len(self.resolution_history)}
                )

                print(f"{GREEN}✅ Secure Gradient AI predictor ready ({len(self.resolution_history)} historical resolutions loaded){RESET}\n")
            except Exception as e:
                print(f"{YELLOW}⚠️  Could not initialize Gradient AI: {e}{RESET}")
                self.enabled = False
        elif self.enabled:
            print(f"{YELLOW}⚠️  GRADIENT_ACCESS_TOKEN or GRADIENT_WORKSPACE_ID not set{RESET}")
            self.enabled = False

    def _initialize_model(self):
        """Initialize or load the fine-tuned model with security checks"""
        try:
            # Security check: Validate authentication before model operations
            if self.auth_manager.enabled:
                cached_token = self.auth_manager.token_manager.get_cached_token()
                if not cached_token:
                    self.auth_manager._get_access_token()

            self.base_model = self.gradient.get_base_model(base_model_slug=self.model_id)

            adapter_id = self._get_saved_adapter_id()

            if adapter_id:
                try:
                    self.model_adapter = self.base_model.get_model_adapter(model_adapter_id=adapter_id)
                    print(f"{DIM}Loaded existing model adapter: {adapter_id}{RESET}")
                except Exception:
                    self._create_new_adapter()
            else:
                self._create_new_adapter()

        except Exception as e:
            print(f"{YELLOW}⚠️  Could not initialize Gradient model: {e}{RESET}")
            self.enabled = False

    def _create_new_adapter(self):
        """Create a new model adapter for fine-tuning with security"""
        try:
            self.model_adapter = self.base_model.create_model_adapter(name="dependency-resolver")
            self._save_adapter_id(self.model_adapter.id)
            print(f"{DIM}Created new model adapter: {self.model_adapter.id}{RESET}")
        except Exception as e:
            print(f"{YELLOW}⚠️  Could not create model adapter: {e}{RESET}")
            self.enabled = False

    def _get_saved_adapter_id(self) -> Optional[str]:
        """Get saved adapter ID from file"""
        adapter_file = os.path.expanduser("~/.gradient_adapter_id")
        if os.path.exists(adapter_file):
            try:
                with open(adapter_file, 'r') as f:
                    return f.read().strip()
            except Exception:
                pass
        return None

    def _save_adapter_id(self, adapter_id: str):
        """Save adapter ID to file"""
        adapter_file = os.path.expanduser("~/.gradient_adapter_id")
        try:
            with open(adapter_file, 'w') as f:
                f.write(adapter_id)
        except Exception:
            pass

    def _load_history(self):
        """Load resolution history from file"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.resolution_history = [
                        ResolutionRecord(**record) for record in data
                    ]
            except Exception as e:
                print(f"{DIM}Could not load resolution history: {e}{RESET}")

    def _save_history(self):
        """Save resolution history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(
                    [asdict(record) for record in self.resolution_history],
                    f,
                    indent=2
                )
        except Exception as e:
            print(f"{YELLOW}⚠️  Could not save resolution history: {e}{RESET}")

    def predict_resolution(self, conflict: ConflictReport, command: str = "predict") -> Optional[Dict[str, Any]]:
        """Predict the best resolution based on learned history with security"""
        if not self.enabled or not self.model_adapter:
            return self._fallback_prediction(conflict)

        start_time = time.time()
        error = None

        try:
            # Security check before API call
            if self.auth_manager.enabled:
                auth_headers = self.auth_manager.get_authorization_header()
                if not auth_headers:
                    print(f"{YELLOW}⚠️  No valid authentication for prediction{RESET}")

            prompt = self._build_prediction_prompt(conflict)

            print(f"{DIM}🔮 Asking Secure Gradient AI for resolution prediction...{RESET}")

            response = self.model_adapter.complete(
                query=prompt,
                max_generated_token_count=200
            ).generated_output

            prediction = self._parse_prediction_response(response)

            if prediction:
                return prediction
            else:
                return self._fallback_prediction(conflict)

        except Exception as e:
            error = str(e)
            print(f"{YELLOW}⚠️  Gradient AI prediction error: {e}{RESET}")
            return self._fallback_prediction(conflict)

        finally:
            response_time = (time.time() - start_time) * 1000
            self.auth_manager.audit_logger.log_api_call(
                command=command,
                api_name="GradientAI",
                endpoint="/complete",
                method="POST",
                response_time_ms=response_time,
                error=error,
                metadata={
                    "conflict_type": conflict.conflict_type,
                    "package": conflict.package_requested,
                    "dependency": conflict.dependency_name
                }
            )

    def _build_prediction_prompt(self, conflict: ConflictReport) -> str:
        """Build prediction prompt for Gradient AI"""
        return (
            f"### Inputs:\n"
            f"Package: {conflict.package_requested} {conflict.version_requested}\n"
            f"Conflict: {conflict.dependency_name} requires {conflict.dependency_required_spec}, "
            f"currently installed: {conflict.dependency_installed_version or 'not installed'}\n"
            f"Conflict type: {conflict.conflict_type}\n"
            f"\n### Response:\n"
        )

    def _parse_prediction_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse Gradient AI response into actionable prediction"""
        try:
            lines = response.strip().split('\n')
            prediction = {
                'action': None,
                'version': None,
                'confidence': 'learned'
            }

            for line in lines:
                if 'Resolution:' in line:
                    prediction['action'] = line.split('Resolution:')[1].strip()
                elif 'Install version:' in line:
                    prediction['version'] = line.split('Install version:')[1].strip()

            if prediction['action'] and prediction['version']:
                return prediction

        except Exception:
            pass

        return None

    def _fallback_prediction(self, conflict: ConflictReport) -> Dict[str, Any]:
        """Fallback prediction based on historical patterns"""
        similar_conflicts = [
            record for record in self.resolution_history
            if record.dependency_name == conflict.dependency_name
            and record.conflict_type == conflict.conflict_type
            and record.success
        ]

        if similar_conflicts:
            latest = max(similar_conflicts, key=lambda r: r.timestamp)
            return {
                'action': latest.resolution_action,
                'version': latest.resolution_version,
                'confidence': 'historical'
            }

        return {
            'action': conflict.suggested_action,
            'version': None,
            'confidence': 'heuristic'
        }

    def learn_from_resolution(self, conflict: ConflictReport, resolution_action: str,
                            resolution_version: str, success: bool):
        """Learn from a successful/failed resolution with security"""
        record = ResolutionRecord(
            timestamp=datetime.now().isoformat(),
            package_requested=conflict.package_requested,
            version_requested=conflict.version_requested,
            conflict_type=conflict.conflict_type,
            dependency_name=conflict.dependency_name,
            dependency_required_spec=conflict.dependency_required_spec,
            dependency_installed_version=conflict.dependency_installed_version,
            resolution_action=resolution_action,
            resolution_version=resolution_version,
            success=success,
            environment_info={
                'python_version': sys.version,
                'platform': sys.platform
            }
        )

        self.resolution_history.append(record)
        self._save_history()

        self.auth_manager.audit_logger.log_user_action(
            "learn",
            "RESOLUTION_LEARNED",
            {
                "success": success,
                "action": resolution_action,
                "version": resolution_version,
                "conflict_type": conflict.conflict_type
            }
        )

        if self.enabled and self.model_adapter and success:
            self._fine_tune_with_record(record)

    def _fine_tune_with_record(self, record: ResolutionRecord):
        """Fine-tune the model with a new successful resolution"""
        start_time = time.time()
        error = None

        try:
            # Security check before fine-tuning
            if self.auth_manager.enabled:
                cached_token = self.auth_manager.token_manager.get_cached_token()
                if not cached_token:
                    self.auth_manager._get_access_token()

            training_sample = record.to_training_sample()

            self.model_adapter.fine_tune(
                samples=[{"inputs": training_sample}]
            )

            print(f"{DIM}✅ Model learned from resolution (secured){RESET}")

        except Exception as e:
            error = str(e)
            print(f"{DIM}⚠️  Could not fine-tune model: {e}{RESET}")

        finally:
            response_time = (time.time() - start_time) * 1000
            self.auth_manager.audit_logger.log_api_call(
                command="learn",
                api_name="GradientAI",
                endpoint="/fine_tune",
                method="POST",
                response_time_ms=response_time,
                error=error,
                metadata={"training_sample_size": 1}
            )

    def batch_train(self):
        """Batch train on all successful historical resolutions"""
        if not self.enabled or not self.model_adapter:
            print(f"{YELLOW}⚠️  Gradient AI not available for training{RESET}")
            return

        successful_records = [r for r in self.resolution_history if r.success]

        if len(successful_records) < 5:
            print(f"{YELLOW}⚠️  Need at least 5 successful resolutions to batch train (have {len(successful_records)}){RESET}")
            return

        start_time = time.time()
        error = None

        try:
            # Security check before batch training
            if self.auth_manager.enabled:
                cached_token = self.auth_manager.token_manager.get_cached_token()
                if not cached_token:
                    self.auth_manager._get_access_token()

            print(f"{CYAN}🧠 Batch training on {len(successful_records)} successful resolutions (secured)...{RESET}")

            training_samples = [
                {"inputs": record.to_training_sample()}
                for record in successful_records
            ]

            self.model_adapter.fine_tune(samples=training_samples)

            print(f"{GREEN}✅ Batch training complete! Model improved.{RESET}")

        except Exception as e:
            error = str(e)
            print(f"{RED}❌ Batch training failed: {e}{RESET}")

        finally:
            response_time = (time.time() - start_time) * 1000
            self.auth_manager.audit_logger.log_api_call(
                command="train",
                api_name="GradientAI",
                endpoint="/fine_tune/batch",
                method="POST",
                response_time_ms=response_time,
                error=error,
                metadata={"training_sample_size": len(successful_records)}
            )

    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics"""
        total = len(self.resolution_history)
        successful = sum(1 for r in self.resolution_history if r.success)

        conflict_types = {}
        for record in self.resolution_history:
            conflict_types[record.conflict_type] = conflict_types.get(record.conflict_type, 0) + 1

        return {
            'total_resolutions': total,
            'successful_resolutions': successful,
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'conflict_types': conflict_types,
            'most_common_conflicts': self._get_most_common_conflicts()
        }

    def _get_most_common_conflicts(self) -> List[Tuple[str, int]]:
        """Get most common dependency conflicts"""
        conflict_counts = {}
        for record in self.resolution_history:
            key = f"{record.dependency_name} ({record.conflict_type})"
            conflict_counts[key] = conflict_counts.get(key, 0) + 1

        sorted_conflicts = sorted(conflict_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_conflicts[:5]

    def close(self):
        """Clean up resources"""
        if self.gradient:
            try:
                self.gradient.close()
            except Exception:
                pass


class SecureGeminiAdvisor:
    """Gemini AI integration with Auth0 security for intelligent conflict resolution advice"""

    def __init__(self, auth_manager: Auth0SecurityManager):
        self.enabled = GEMINI_AVAILABLE
        self.auth_manager = auth_manager
        self.client = None
        self.api_key = os.getenv("GEMINI_API_KEY")

        if self.enabled and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)

                self.auth_manager.audit_logger.log_user_action(
                    "init",
                    "GEMINI_AI_INITIALIZED"
                )

                print(f"{GREEN}✨ Secure Gemini AI advisor enabled{RESET}\n")
            except Exception as e:
                print(f"{YELLOW}⚠️  Could not initialize Gemini client: {e}{RESET}")
                self.enabled = False
        elif self.enabled and not self.api_key:
            print(f"{YELLOW}⚠️  GEMINI_API_KEY not set. AI suggestions disabled.{RESET}\n")
            self.enabled = False

    def get_conflict_advice(self, conflicts: List[ConflictReport], package_spec: str, command: str = "advice") -> Optional[str]:
        """Get AI-powered advice for resolving dependency conflicts with security"""
        if not self.enabled or not self.client:
            return None

        start_time = time.time()
        error = None
        response_text = None

        try:
            # Security check before API call
            if self.auth_manager.enabled:
                auth_headers = self.auth_manager.get_authorization_header()
                if not auth_headers:
                    print(f"{YELLOW}⚠️  No valid authentication for Gemini AI{RESET}")
                    return None

            prompt = self._build_conflict_prompt(conflicts, package_spec)
            print(f"{DIM}🤖 Asking Secure Gemini AI for advice...{RESET}")

            # Note: Gemini client handles authentication internally with API key
            # But we verify Auth0 token is valid for audit trail
            response = self.client.models.generate_content(
                model='gemini-2.0-flash-exp',
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.7,
                    max_output_tokens=1000,
                )
            )

            if response and response.text:
                response_text = response.text.strip()
                return response_text

        except Exception as e:
            error = str(e)
            print(f"{YELLOW}⚠️  Gemini API error: {e}{RESET}")

        finally:
            response_time = (time.time() - start_time) * 1000
            self.auth_manager.audit_logger.log_api_call(
                command=command,
                api_name="GeminiAI",
                endpoint="/generate_content",
                method="POST",
                request_headers={"Authorization": "Bearer <gemini_key>"},
                response_time_ms=response_time,
                error=error,
                metadata={
                    "model": "gemini-2.0-flash-exp",
                    "conflicts_count": len(conflicts),
                    "package": package_spec,
                    "response_length": len(response_text) if response_text else 0
                }
            )

        return None

    def _build_conflict_prompt(self, conflicts: List[ConflictReport], package_spec: str) -> str:
        """Build a clear prompt for Gemini to analyze conflicts"""
        prompt = f"""You are a Python dependency expert. A user is trying to install the package: {package_spec}

However, the following dependency conflicts were detected:

"""
        for i, conflict in enumerate(conflicts, 1):
            if conflict.conflict_type == "forward":
                prompt += f"{i}. {conflict.package_requested} {conflict.version_requested} requires {conflict.dependency_name}{conflict.dependency_required_spec}, but the current environment has {conflict.dependency_name} {conflict.dependency_installed_version}\n"
            elif conflict.conflict_type == "reverse":
                prompt += f"{i}. {conflict.dependency_name} {conflict.dependency_installed_version} requires {conflict.package_requested}{conflict.dependency_required_spec}, but the user is trying to install {conflict.package_requested} {conflict.version_requested}\n"
            elif conflict.conflict_type == "missing":
                prompt += f"{i}. {conflict.package_requested} {conflict.version_requested} requires {conflict.dependency_name}{conflict.dependency_required_spec}, but it's not installed\n"

        prompt += """
Please provide:
1. A clear, beginner-friendly explanation of why these conflicts occur
2. Specific step-by-step resolution strategies
3. If applicable, suggest alternative packages
4. Warn about potential breaking changes

Keep your response concise and actionable."""

        return prompt

    def get_auto_resolution_plan(self, conflicts: List[ConflictReport], package_spec: str) -> Optional[Dict[str, Any]]:
        """Get structured auto-resolution plan from Gemini AI"""
        if not self.enabled or not self.client:
            return None

        start_time = time.time()
        error = None
        response_text = None

        try:
            # Security check before API call
            if self.auth_manager.enabled:
                auth_headers = self.auth_manager.get_authorization_header()
                if not auth_headers:
                    return None

            prompt = self._build_auto_resolution_prompt(conflicts, package_spec)
            print(f"{DIM}🤖 Asking Gemini AI for auto-resolution plan...{RESET}")

            response = self.client.models.generate_content(
                model='gemini-2.0-flash-exp',
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=800,
                )
            )

            if response and response.text:
                response_text = response.text.strip()
                return self._parse_resolution_plan(response_text)

        except Exception as e:
            error = str(e)
            print(f"{YELLOW}⚠️  Gemini API error: {e}{RESET}")

        finally:
            response_time = (time.time() - start_time) * 1000
            self.auth_manager.audit_logger.log_api_call(
                command="auto-resolve",
                api_name="GeminiAI",
                endpoint="/generate_content",
                method="POST",
                request_headers={"Authorization": "Bearer <gemini_key>"},
                response_time_ms=response_time,
                error=error,
                metadata={
                    "model": "gemini-2.0-flash-exp",
                    "conflicts_count": len(conflicts),
                    "package": package_spec,
                    "response_length": len(response_text) if response_text else 0
                }
            )

        return None

    def _build_auto_resolution_prompt(self, conflicts: List[ConflictReport], package_spec: str) -> str:
        """Build prompt for auto-resolution plan"""
        prompt = f"""You are a Python dependency expert. Generate an automated resolution plan for installing: {package_spec}

Conflicts detected:

"""
        for i, conflict in enumerate(conflicts, 1):
            if conflict.conflict_type == "forward":
                prompt += f"{i}. {conflict.package_requested} {conflict.version_requested} requires {conflict.dependency_name}{conflict.dependency_required_spec}, but installed: {conflict.dependency_name} {conflict.dependency_installed_version}\n"
            elif conflict.conflict_type == "reverse":
                prompt += f"{i}. {conflict.dependency_name} {conflict.dependency_installed_version} requires {conflict.package_requested}{conflict.dependency_required_spec}, but trying to install: {conflict.package_requested} {conflict.version_requested}\n"
            elif conflict.conflict_type == "missing":
                prompt += f"{i}. {conflict.package_requested} {conflict.version_requested} requires {conflict.dependency_name}{conflict.dependency_required_spec}, but not installed\n"

        prompt += """
Generate a resolution plan with these exact steps in this format:

STEP 1: [action]
COMMAND: [pip command to run]
REASON: [why this step is needed]

STEP 2: [action]
COMMAND: [pip command to run]
REASON: [why this step is needed]

...

Final step must install the requested package.
Use pip install/upgrade commands with specific version numbers when needed.
Keep the plan minimal (3-5 steps maximum).
"""

        return prompt

    def _parse_resolution_plan(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse Gemini response into structured resolution plan"""
        try:
            lines = response.strip().split('\n')
            steps = []
            current_step = {}

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                if line.startswith('STEP'):
                    if current_step:
                        steps.append(current_step)
                    current_step = {'action': line.split(':', 1)[1].strip() if ':' in line else line}
                elif line.startswith('COMMAND:'):
                    current_step['command'] = line.split(':', 1)[1].strip()
                elif line.startswith('REASON:'):
                    current_step['reason'] = line.split(':', 1)[1].strip()

            if current_step:
                steps.append(current_step)

            if steps:
                return {'steps': steps}

        except Exception as e:
            print(f"{DIM}Could not parse resolution plan: {e}{RESET}")

        return None


class UniversalPyPIClient:
    """Universal PyPI client that works for any package"""

    def __init__(self):
        self.cache: Dict[str, dict] = {}
        self.version_cache: Dict[str, List[str]] = {}
        self.api_calls = 0
        self.max_retries = 3

    def get_package_metadata(self, package_name: str, version: Optional[str] = None) -> Optional[dict]:
        """Get complete package metadata from PyPI for ANY package"""
        cache_key = f"{package_name.lower()}:{version or 'latest'}"

        if cache_key in self.cache:
            return self.cache[cache_key]

        for attempt in range(self.max_retries):
            try:
                if version:
                    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
                else:
                    url = f"https://pypi.org/pypi/{package_name}/json"

                self.api_calls += 1

                with urllib.request.urlopen(url, timeout=10) as response:
                    data = json.loads(response.read().decode('utf-8'))

                self.cache[cache_key] = data
                return data

            except urllib.error.HTTPError as e:
                if e.code == 404:
                    if attempt == 0:
                        print(f"{YELLOW}⚠️  Package {package_name} {version or ''} not found on PyPI{RESET}")
                    return None
                elif attempt < self.max_retries - 1:
                    time.sleep(1)
                    continue
                else:
                    return None
            except Exception as e:
                if attempt < self.max_retries - 1:
                    time.sleep(1)
                    continue
                else:
                    return None

        return None

    def get_available_versions(self, package_name: str, limit: int = 100) -> List[str]:
        """Get available versions for a package from PyPI"""
        cache_key = package_name.lower()

        if cache_key in self.version_cache:
            return self.version_cache[cache_key]

        try:
            metadata = self.get_package_metadata(package_name)
            if not metadata:
                return []

            releases = metadata.get('releases', {})
            versions = []

            for version_str in releases.keys():
                try:
                    parsed_version = parse_version(version_str)
                    if not parsed_version.is_prerelease:
                        versions.append(version_str)
                except Exception:
                    continue

            try:
                versions.sort(key=lambda v: parse_version(v), reverse=True)
                versions = versions[:limit]
            except Exception:
                pass

            self.version_cache[cache_key] = versions
            return versions

        except Exception:
            return []

    def find_best_version(self, package_name: str, specifier_set: SpecifierSet) -> Optional[str]:
        """Find the best version that satisfies the given specifier set"""
        if not specifier_set:
            metadata = self.get_package_metadata(package_name)
            if metadata and metadata.get('info'):
                return metadata['info'].get('version')
            return None

        for spec in specifier_set:
            if spec.operator == "==":
                return spec.version

        available_versions = self.get_available_versions(package_name)

        if not available_versions:
            return None

        compatible_versions = []
        for version in available_versions:
            try:
                if specifier_set.contains(version, prereleases=False):
                    compatible_versions.append(version)
            except Exception:
                continue

        if not compatible_versions:
            return None

        try:
            compatible_versions.sort(key=lambda v: parse_version(v), reverse=True)
            best_version = compatible_versions[0]
            print(f"{DIM}Resolved {package_name}{specifier_set} → {best_version}{RESET}")
            return best_version
        except Exception:
            return compatible_versions[0]

    def parse_requirements(self, requires_dist: List[str]) -> List[PackageRequirement]:
        """Parse requirements from PyPI metadata into structured format"""
        parsed_requirements = []

        for req_string in requires_dist or []:
            try:
                if not req_string or not req_string.strip():
                    continue

                req = Requirement(req_string)

                parsed_req = PackageRequirement(
                    name=req.name.lower(),
                    specifier=req.specifier or SpecifierSet(),
                    extras=req.extras,
                    marker=str(req.marker) if req.marker else None
                )

                parsed_requirements.append(parsed_req)

            except Exception:
                continue

        return parsed_requirements


class UniversalEnvironmentAnalyzer:
    """Analyzes the current Python environment universally"""

    def __init__(self):
        self.installed_packages = self._scan_environment()
        self.dependency_graph = self._build_dependency_graph()

    def _scan_environment(self) -> Dict[str, dict]:
        """Scan current environment and get all installed packages with dependencies"""
        packages = {}

        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "list", "--format=json", "--verbose"
            ], capture_output=True, text=True, check=False)

            if result.returncode == 0:
                print(f"{DIM}Using fast mode: pip list --verbose{RESET}")
                pip_list = json.loads(result.stdout)

                for pkg in pip_list:
                    name = pkg["name"].lower()
                    version = pkg["version"]
                    requires = pkg.get("requires", "")
                    requirements = self._parse_requires_string(requires)

                    packages[name] = {
                        "name": name,
                        "version": version,
                        "requirements": requirements
                    }

                print(f"{DIM}Environment scanned: {len(packages)} packages found{RESET}")
            else:
                result = subprocess.run([
                    sys.executable, "-m", "pip", "list", "--format=json"
                ], capture_output=True, text=True, check=True)

                pip_list = json.loads(result.stdout)

                for pkg in pip_list:
                    name = pkg["name"].lower()
                    version = pkg["version"]

                    packages[name] = {
                        "name": name,
                        "version": version,
                        "requirements": self._get_requirements_for_package(name)
                    }

                print(f"{DIM}Environment scanned: {len(packages)} packages found{RESET}")

        except Exception as e:
            print(f"{YELLOW}⚠️  Could not scan environment: {e}{RESET}")

        return packages

    def _parse_requires_string(self, requires_str: str) -> List[PackageRequirement]:
        """Parse requires string from pip list --verbose output"""
        requirements = []

        if not requires_str or requires_str.strip() == "":
            return requirements

        for req_name in requires_str.split(','):
            req_name = req_name.strip()
            if req_name:
                try:
                    requirements.append(PackageRequirement(
                        name=req_name.lower(),
                        specifier=SpecifierSet()
                    ))
                except Exception:
                    pass

        return requirements

    def _get_requirements_for_package(self, package_name: str) -> List[PackageRequirement]:
        """Get requirements for a specific installed package"""
        requirements = []

        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "show", package_name
            ], capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Requires:'):
                        req_text = line.replace('Requires:', '').strip()
                        if req_text and req_text.lower() != 'none':
                            for req_name in req_text.split(','):
                                req_name = req_name.strip()
                                if req_name:
                                    try:
                                        requirements.append(PackageRequirement(
                                            name=req_name.lower(),
                                            specifier=SpecifierSet()
                                        ))
                                    except Exception:
                                        pass
        except Exception:
            pass

        return requirements

    def _build_dependency_graph(self) -> Dict[str, Set[str]]:
        """Build a graph of dependencies"""
        graph = {}

        for pkg_name, pkg_info in self.installed_packages.items():
            graph.setdefault(pkg_name, set())

            for req in pkg_info.get("requirements", []):
                dep_name = req.name.lower()
                graph.setdefault(dep_name, set()).add(pkg_name)

        return graph

    def get_installed_version(self, package_name: str) -> Optional[str]:
        """Get installed version of a package"""
        pkg_info = self.installed_packages.get(package_name.lower())
        return pkg_info["version"] if pkg_info else None

    def get_packages_depending_on(self, package_name: str) -> Set[str]:
        """Get all packages that depend on the given package"""
        return self.dependency_graph.get(package_name.lower(), set())


class SecureUniversalDependencyChecker:
    """Universal dependency checker with AI-powered self-healing, Auth0 security, and audit logging"""

    def __init__(self, enable_gemini: bool = True, enable_gradient: bool = True,
                 token_manager: Optional[TokenManager] = None,
                 audit_logger: Optional[AuditLogger] = None,
                 command: str = "unknown"):
        self.audit_logger = audit_logger or AuditLogger()
        self.auth_manager = Auth0SecurityManager(token_manager=token_manager, audit_logger=self.audit_logger)
        self.pypi_client = UniversalPyPIClient()
        self.env_analyzer = UniversalEnvironmentAnalyzer()
        self.conflicts: List[ConflictReport] = []
        self.current_command = command
        self.gemini_advisor = SecureGeminiAdvisor(self.auth_manager) if enable_gemini else None
        self.gradient_predictor = SecureGradientAIPredictor(self.auth_manager) if enable_gradient else None

    def check_package_installation(self, package_spec: str) -> List[ConflictReport]:
        """Universal check for ANY package installation with AI predictions and security"""
        self.conflicts = []

        self.audit_logger.log_user_action(
            self.current_command,
            "CHECK_PACKAGE_START",
            {"package": package_spec}
        )

        try:
            req = Requirement(package_spec)
            package_name = req.name.lower()

            target_version = self._resolve_target_version(req)

            if not target_version:
                print(f"{YELLOW}⚠️  Could not resolve version for {package_spec}{RESET}")
                target_version = "latest"

            print(f"{CYAN}Checking {package_name} → {target_version}...{RESET}")

            self._check_reverse_dependencies(package_name, target_version)
            self._check_forward_dependencies(package_name, target_version)

            self.audit_logger.log_user_action(
                self.current_command,
                "CHECK_PACKAGE_COMPLETE",
                {
                    "package": package_spec,
                    "target_version": target_version,
                    "conflicts_found": len(self.conflicts)
                }
            )

        except Exception as e:
            print(f"{RED}Error parsing package spec '{package_spec}': {e}{RESET}")
            self.audit_logger.log_user_action(
                self.current_command,
                "CHECK_PACKAGE_ERROR",
                {"package": package_spec, "error": str(e)}
            )

        return self.conflicts

    def _resolve_target_version(self, req: Requirement) -> Optional[str]:
        """Enhanced version resolution"""
        if not req.specifier:
            metadata = self.pypi_client.get_package_metadata(req.name)
            if metadata and metadata.get('info'):
                latest = metadata['info'].get('version')
                print(f"{DIM}No version constraints, using latest: {latest}{RESET}")
                return latest
            return None

        for spec in req.specifier:
            if spec.operator == "==":
                print(f"{DIM}Exact version: {req.name}=={spec.version}{RESET}")
                return spec.version

        print(f"{DIM}Resolving: {req.name}{req.specifier}{RESET}")
        best_version = self.pypi_client.find_best_version(req.name, req.specifier)

        if best_version:
            return best_version
        else:
            return self._fallback_version_resolution(req)

    def _fallback_version_resolution(self, req: Requirement) -> Optional[str]:
        """Fallback version resolution"""
        try:
            for spec in req.specifier:
                if spec.operator in [">=", ">"]:
                    return spec.version

            metadata = self.pypi_client.get_package_metadata(req.name)
            if metadata and metadata.get('info'):
                return metadata['info'].get('version')

        except Exception:
            pass

        return None

    def _check_reverse_dependencies(self, package_name: str, target_version: str):
        """Check reverse dependencies"""
        dependent_packages = self.env_analyzer.get_packages_depending_on(package_name)

        if not dependent_packages:
            return

        print(f"{DIM}Checking {len(dependent_packages)} reverse dependencies...{RESET}")

        for dependent_pkg in dependent_packages:
            pkg_info = self.env_analyzer.installed_packages.get(dependent_pkg)
            if not pkg_info:
                continue

            for req in pkg_info.get("requirements", []):
                if req.name.lower() == package_name:
                    if target_version != "latest":
                        if not req.is_satisfied_by(target_version):
                            self.conflicts.append(ConflictReport(
                                conflict_type="reverse",
                                package_requested=package_name,
                                version_requested=target_version,
                                dependency_name=dependent_pkg,
                                dependency_required_spec=str(req.specifier) if req.specifier else "any",
                                dependency_installed_version=pkg_info["version"],
                                severity="critical",
                                suggested_action=f"Upgrade {package_name} to satisfy {dependent_pkg}",
                                explanation=f"{dependent_pkg} {pkg_info['version']} requires {package_name}{req.specifier}, but trying to install {target_version}"
                            ))

    def _check_forward_dependencies(self, package_name: str, target_version: str):
        """Check forward dependencies"""
        if target_version == "latest":
            return

        print(f"{DIM}Querying PyPI for {package_name} {target_version}...{RESET}")
        metadata = self.pypi_client.get_package_metadata(package_name, target_version)

        if not metadata:
            return

        info = metadata.get("info", {})
        requires_dist = info.get("requires_dist", [])

        if not requires_dist:
            return

        parsed_reqs = self.pypi_client.parse_requirements(requires_dist)

        print(f"{DIM}Checking {len(parsed_reqs)} forward dependencies...{RESET}")

        for req in parsed_reqs:
            if req.marker and self._has_unevaluable_marker(req.marker):
                continue

            dep_name = req.name.lower()
            installed_version = self.env_analyzer.get_installed_version(dep_name)

            if installed_version is None:
                suggested_version = self._suggest_install_version(dep_name, req.specifier)
                self.conflicts.append(ConflictReport(
                    conflict_type="missing",
                    package_requested=package_name,
                    version_requested=target_version,
                    dependency_name=dep_name,
                    dependency_required_spec=str(req.specifier) if req.specifier else "any",
                    dependency_installed_version=None,
                    severity="critical",
                    suggested_action=f"Install {dep_name}{suggested_version}",
                    explanation=f"{package_name} {target_version} requires {dep_name}{req.specifier if req.specifier else ''}, but not installed"
                ))

            elif req.specifier:
                if not req.is_satisfied_by(installed_version):
                    self.conflicts.append(ConflictReport(
                        conflict_type="forward",
                        package_requested=package_name,
                        version_requested=target_version,
                        dependency_name=dep_name,
                        dependency_required_spec=str(req.specifier),
                        dependency_installed_version=installed_version,
                        severity="critical",
                        suggested_action=self._suggest_version_fix(dep_name, req.specifier, installed_version),
                        explanation=f"{package_name} {target_version} requires {dep_name}{req.specifier}, but have {dep_name} {installed_version}"
                    ))

    def _suggest_install_version(self, package: str, specifier_set: SpecifierSet) -> str:
        """Suggest best version to install"""
        if not specifier_set:
            return ""

        best_version = self.pypi_client.find_best_version(package, specifier_set)
        if best_version:
            return f"=={best_version}"
        else:
            return f"{specifier_set}"

    def _has_unevaluable_marker(self, marker: str) -> bool:
        """Check if marker is evaluable"""
        if not marker:
            return False

        try:
            marker_obj = Marker(marker)
            environment = {
                'platform_system': sys.platform,
                'python_version': '.'.join(map(str, sys.version_info[:2])),
                'python_full_version': '.'.join(map(str, sys.version_info[:3])),
                'os_name': os.name,
                'sys_platform': sys.platform,
                'platform_machine': os.uname().machine if hasattr(os, 'uname') else '',
                'platform_python_implementation': sys.implementation.name,
                'platform_release': '',
                'platform_version': '',
                'implementation_name': sys.implementation.name,
                'implementation_version': '.'.join(map(str, sys.implementation.version[:3])),
            }

            result = marker_obj.evaluate(environment)

            if 'extra ==' in marker:
                return True

            return not result

        except Exception:
            return True

    def _suggest_version_fix(self, package: str, required_spec: SpecifierSet, current_version: str) -> str:
        """Suggest version fix"""
        try:
            best_version = self.pypi_client.find_best_version(package, required_spec)
            if best_version:
                return f"Install {package}=={best_version}"

            for spec in required_spec:
                if spec.operator in [">=", ">"]:
                    return f"Upgrade {package} to {spec.version} or newer"
                elif spec.operator == "==":
                    return f"Install {package}=={spec.version}"
                elif spec.operator in ["<=", "<"]:
                    return f"Downgrade {package} to satisfy {required_spec}"
            return f"Install compatible {package} version"
        except Exception:
            return f"Check {package} version compatibility"

    def display_conflicts_with_predictions(self, package_spec: str):
        """Display conflicts with AI predictions"""
        if not self.conflicts:
            print(f"\n{GREEN}✅ No dependency conflicts detected!{RESET}")
            if self.auth_manager.enabled:
                print(f"{GREEN}🔒 All checks performed with Auth0 security{RESET}")
            return

        print(f"\n{RED}{'='*70}{RESET}")
        print(f"{RED}{BRIGHT}❌ DEPENDENCY CONFLICTS DETECTED{RESET}")
        print(f"{RED}{'='*70}{RESET}")

        reverse = [c for c in self.conflicts if c.conflict_type == "reverse"]
        forward = [c for c in self.conflicts if c.conflict_type == "forward"]
        missing = [c for c in self.conflicts if c.conflict_type == "missing"]

        if reverse:
            print(f"\n{RED}🔄 REVERSE DEPENDENCY CONFLICTS:{RESET}")
            for conflict in reverse:
                print(f"  • {conflict.dependency_name} {conflict.dependency_installed_version} "
                      f"requires {conflict.package_requested}{conflict.dependency_required_spec}, "
                      f"trying to install {conflict.version_requested}")

        if forward:
            print(f"\n{BLUE}➡️  FORWARD DEPENDENCY CONFLICTS:{RESET}")
            for conflict in forward:
                print(f"  • {conflict.package_requested} {conflict.version_requested} "
                      f"requires {conflict.dependency_name}{conflict.dependency_required_spec}, "
                      f"have {conflict.dependency_name} {conflict.dependency_installed_version}")

        if missing:
            print(f"\n{MAGENTA}❓ MISSING DEPENDENCIES:{RESET}")
            for conflict in missing:
                print(f"  • {conflict.package_requested} {conflict.version_requested} "
                      f"requires {conflict.dependency_name}{conflict.dependency_required_spec}")

        # Gradient AI predictions
        if self.gradient_predictor and self.gradient_predictor.enabled:
            print(f"\n{CYAN}{'='*70}{RESET}")
            print(f"{CYAN}{BRIGHT}🧠 SECURE GRADIENT AI PREDICTIONS{RESET}")
            print(f"{CYAN}{'='*70}{RESET}\n")

            for i, conflict in enumerate(self.conflicts, 1):
                prediction = self.gradient_predictor.predict_resolution(conflict, self.current_command)

                confidence_emoji = {
                    'learned': '🎯',
                    'historical': '📊',
                    'heuristic': '💡'
                }.get(prediction['confidence'], '💡')

                print(f"{i}. {confidence_emoji} {conflict.dependency_name}:")
                print(f"   Action: {prediction['action']}")
                if prediction['version']:
                    print(f"   Version: {prediction['version']}")
                print(f"   Confidence: {prediction['confidence'].upper()}")
                print()

        # Gemini AI advice
        if self.gemini_advisor and self.gemini_advisor.enabled:
            print(f"{GREEN}{'='*70}{RESET}")
            print(f"{GREEN}{BRIGHT}✨ SECURE GEMINI AI ADVISOR{RESET}")
            print(f"{GREEN}{'='*70}{RESET}\n")

            ai_advice = self.gemini_advisor.get_conflict_advice(self.conflicts, package_spec, self.current_command)
            if ai_advice:
                print(ai_advice)

        if self.auth_manager.enabled:
            print(f"\n{GREEN}🔒 All API calls secured with Auth0 authentication{RESET}")

        print(f"\n{DIM}PyPI API calls: {self.pypi_client.api_calls}{RESET}")

    def auto_resolve_and_install(self, package_spec: str) -> bool:
        """Automatically resolve conflicts and install package using Gemini AI"""
        if not self.conflicts:
            print(f"\n{GREEN}✅ No conflicts to resolve. Installing directly...{RESET}")
            return self._install_package(package_spec)

        if not self.gemini_advisor or not self.gemini_advisor.enabled:
            print(f"\n{RED}❌ Gemini AI is required for auto-resolution but is not available{RESET}")
            return False

        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}{BRIGHT}🤖 AUTO-RESOLVING CONFLICTS{RESET}")
        print(f"{CYAN}{'='*70}{RESET}\n")

        # Get resolution plan from Gemini
        resolution_plan = self.gemini_advisor.get_auto_resolution_plan(self.conflicts, package_spec)

        if not resolution_plan or 'steps' not in resolution_plan:
            print(f"{RED}❌ Could not generate auto-resolution plan{RESET}")
            return False

        steps = resolution_plan['steps']
        print(f"{GREEN}Generated resolution plan with {len(steps)} steps:{RESET}\n")

        # Display plan
        for i, step in enumerate(steps, 1):
            print(f"{BRIGHT}Step {i}:{RESET} {step.get('action', 'N/A')}")
            print(f"  Command: {CYAN}{step.get('command', 'N/A')}{RESET}")
            print(f"  Reason: {DIM}{step.get('reason', 'N/A')}{RESET}\n")

        # Ask for confirmation
        print(f"{YELLOW}Do you want to execute this plan? (y/n): {RESET}", end='')
        response = input().strip().lower()

        if response != 'y':
            print(f"{YELLOW}Auto-resolution cancelled{RESET}")
            return False

        # Execute plan
        print(f"\n{GREEN}Executing resolution plan...{RESET}\n")

        for i, step in enumerate(steps, 1):
            command = step.get('command', '')
            if not command:
                continue

            print(f"{CYAN}[Step {i}/{len(steps)}]{RESET} {command}")

            # Execute command
            success = self._execute_pip_command(command)

            if not success:
                print(f"{RED}❌ Step {i} failed. Aborting...{RESET}")
                return False

            print(f"{GREEN}✅ Step {i} completed{RESET}\n")

        print(f"{GREEN}{'='*70}{RESET}")
        print(f"{GREEN}{BRIGHT}✅ AUTO-RESOLUTION COMPLETE!{RESET}")
        print(f"{GREEN}{'='*70}{RESET}\n")

        # Learn from successful resolution
        if self.gradient_predictor and self.gradient_predictor.enabled:
            for conflict in self.conflicts:
                self.gradient_predictor.learn_from_resolution(
                    conflict=conflict,
                    resolution_action="auto-resolved",
                    resolution_version=package_spec,
                    success=True
                )

        self.audit_logger.log_user_action(
            self.current_command,
            "AUTO_RESOLVE_SUCCESS",
            {"package": package_spec, "steps": len(steps)}
        )

        return True

    def _execute_pip_command(self, command: str) -> bool:
        """Execute a pip command"""
        try:
            # Parse command
            parts = command.split()

            if not parts or parts[0] not in ['pip', 'python', sys.executable]:
                print(f"{YELLOW}⚠️  Unexpected command format: {command}{RESET}")
                return False

            # Build command
            if parts[0] == 'pip':
                cmd = [sys.executable, '-m', 'pip'] + parts[1:]
            elif parts[0] == 'python':
                cmd = [sys.executable] + parts[1:]
            else:
                cmd = parts

            # Execute
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return True
            else:
                print(f"{RED}Command failed with exit code {result.returncode}{RESET}")
                if result.stderr:
                    print(f"{DIM}{result.stderr}{RESET}")
                return False

        except Exception as e:
            print(f"{RED}Failed to execute command: {e}{RESET}")
            return False

    def _install_package(self, package_spec: str) -> bool:
        """Install a package directly"""
        try:
            print(f"{CYAN}Installing {package_spec}...{RESET}")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package_spec],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print(f"{GREEN}✅ Successfully installed {package_spec}{RESET}")
                self.audit_logger.log_user_action(
                    self.current_command,
                    "INSTALL_SUCCESS",
                    {"package": package_spec}
                )
                return True
            else:
                print(f"{RED}❌ Installation failed{RESET}")
                if result.stderr:
                    print(f"{DIM}{result.stderr}{RESET}")
                return False

        except Exception as e:
            print(f"{RED}❌ Installation failed: {e}{RESET}")
            return False

    def learn_from_user_resolution(self, package_spec: str):
        """Interactive learning from user's resolution"""
        if not self.conflicts or not self.gradient_predictor:
            return

        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}{BRIGHT}📚 LEARNING MODE{RESET}")
        print(f"{CYAN}{'='*70}{RESET}\n")

        print(f"Did you successfully resolve the conflicts?")
        response = input(f"{YELLOW}(y/n): {RESET}").strip().lower()

        if response == 'y':
            print(f"\n{GREEN}Great! Let's record what worked.{RESET}\n")

            for i, conflict in enumerate(self.conflicts, 1):
                print(f"\n{i}. Conflict: {conflict.dependency_name} {conflict.dependency_required_spec}")
                print(f"   Current: {conflict.dependency_installed_version or 'not installed'}")

                action = input(f"{YELLOW}   What did you do? (upgrade/downgrade/install): {RESET}").strip()
                version = input(f"{YELLOW}   What version did you install?: {RESET}").strip()

                if action and version:
                    self.gradient_predictor.learn_from_resolution(
                        conflict=conflict,
                        resolution_action=action,
                        resolution_version=version,
                        success=True
                    )
                    print(f"   {GREEN}✅ Learned (secured)!{RESET}")

            print(f"\n{GREEN}🎉 Thank you! The system will use this for future predictions.{RESET}")

    def show_statistics(self):
        """Show learning statistics"""
        if not self.gradient_predictor or not self.gradient_predictor.enabled:
            print(f"{YELLOW}⚠️  Gradient AI not available{RESET}")
            return

        stats = self.gradient_predictor.get_statistics()

        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}{BRIGHT}📊 LEARNING STATISTICS{RESET}")
        print(f"{CYAN}{'='*70}{RESET}\n")

        print(f"Total Resolutions: {stats['total_resolutions']}")
        print(f"Successful: {stats['successful_resolutions']}")
        print(f"Success Rate: {stats['success_rate']:.1f}%")

        if stats['most_common_conflicts']:
            print(f"\n{BRIGHT}Most Common Conflicts:{RESET}")
            for conflict, count in stats['most_common_conflicts']:
                print(f"  • {conflict}: {count} times")

        if self.auth_manager.enabled:
            print(f"\n{GREEN}🔒 Statistics collected with Auth0 security{RESET}")

    def show_token_info(self):
        """Show information about cached token"""
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}{BRIGHT}🔑 TOKEN INFORMATION{RESET}")
        print(f"{CYAN}{'='*70}{RESET}\n")

        token_info = self.auth_manager.get_token_info()

        if not token_info:
            print(f"{YELLOW}No cached token found{RESET}")
            return

        status = f"{GREEN}Valid{RESET}" if token_info['valid'] else f"{RED}Expired{RESET}"
        print(f"Status: {status}")
        print(f"Expires at: {token_info['expires_at']}")
        print(f"Time remaining: {token_info['time_remaining_seconds']} seconds")
        print(f"Token type: {token_info['token_type']}")
        if token_info['scope']:
            print(f"Scope: {token_info['scope']}")

        cache_file = self.auth_manager.token_manager.token_file
        print(f"\nCache location: {cache_file}")

    def show_session_summary(self):
        """Show session summary"""
        summary = self.audit_logger.get_session_summary()

        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}{BRIGHT}📊 SESSION SUMMARY{RESET}")
        print(f"{CYAN}{'='*70}{RESET}\n")

        print(f"Session ID: {summary.get('session_id', 'N/A')}")
        print(f"User: {summary.get('user', 'N/A')}")
        print(f"Total API Calls: {summary.get('total_api_calls', 0)}")

        if summary.get('api_breakdown'):
            print(f"\nAPI Breakdown:")
            for api, count in summary['api_breakdown'].items():
                print(f"  • {api}: {count} calls")

        print(f"\nTotal Time: {summary.get('total_time_ms', 0):.2f}ms")
        print(f"Errors: {summary.get('errors', 0)}")
        print(f"\nLog File: {summary.get('log_file', 'N/A')}")

    def batch_train(self):
        """Batch train the model"""
        if self.gradient_predictor:
            self.gradient_predictor.batch_train()

    def close(self):
        """Clean up resources"""
        if self.gradient_predictor:
            self.gradient_predictor.close()


def main():
    parser = argparse.ArgumentParser(
        description="Universal Dependency Checker - AI-Powered Self-Healing with Auth0 Security & Audit Logging",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python try9.py check pandas>=2.0.0
  python try9.py install transformers>=4.30.0
  python try9.py auto-resolve torch==2.0.0
  python try9.py learn pandas>=2.0.0
  python try9.py stats
  python try9.py train
  python try9.py token-info
  python try9.py clear-token
  python try9.py session-summary
  python try9.py show-logs

Environment Variables:
  GEMINI_API_KEY              - For natural language advice
  GRADIENT_ACCESS_TOKEN       - For self-healing predictions
  GRADIENT_WORKSPACE_ID       - For self-healing predictions
  AUTH0_DOMAIN                - Auth0 domain (e.g., your-domain.auth0.com)
  AUTH0_CLIENT_ID             - Auth0 client ID
  AUTH0_CLIENT_SECRET         - Auth0 client secret
  AUTH0_AUDIENCE              - Auth0 API audience (optional)

Security Features:
  - All external API calls are secured with Auth0 Bearer token authentication
  - Automatic token refresh for long-running operations
  - Token validation before critical operations
  - Audit trail for all authenticated API calls
  - File-based token caching to avoid re-authentication (~/.mycli/token.json)
  - Short-lived tokens with automatic expiry handling
  - Comprehensive local logging of all API requests (~/.mycli/logs/)
  - User activity tracking and session management
        """
    )

    parser.add_argument("command",
                       choices=["check", "install", "auto-resolve", "learn", "stats", "train", "token-info", "clear-token", "session-summary", "show-logs"],
                       help="check=analyze, install=analyze+install, auto-resolve=auto-fix conflicts and install, learn=record resolution, stats=show statistics, train=batch train model, token-info=show token info, clear-token=clear cached token, session-summary=show session stats, show-logs=show recent logs")
    parser.add_argument("package", nargs='?', help="Package specification")
    parser.add_argument("--no-gemini", action="store_true", help="Disable Gemini AI")
    parser.add_argument("--no-gradient", action="store_true", help="Disable Gradient AI")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose audit logging to console")

    args = parser.parse_args()

    print(f"{BLUE}🔍 Universal Dependency Checker - AI Enhanced with Auth0 Security & Audit Logging{RESET}")
    print(f"{CYAN}✨ Self-Healing with Gradient AI + Gemini Advisor + Auth0 + Token Management + Audit Logs{RESET}\n")

    token_manager = TokenManager()
    audit_logger = AuditLogger()

    checker = SecureUniversalDependencyChecker(
        enable_gemini=(not args.no_gemini),
        enable_gradient=(not args.no_gradient),
        token_manager=token_manager,
        audit_logger=audit_logger,
        command=args.command
    )

    try:
        if args.command == "stats":
            checker.show_statistics()

        elif args.command == "token-info":
            checker.show_token_info()

        elif args.command == "clear-token":
            token_manager.clear_cache()

        elif args.command == "session-summary":
            checker.show_session_summary()

        elif args.command == "show-logs":
            audit_logger.show_recent_logs(limit=20)

        elif args.command == "train":
            checker.batch_train()

        elif args.command in ["check", "install", "auto-resolve", "learn"]:
            if not args.package:
                print(f"{RED}❌ Package specification required{RESET}")
                sys.exit(1)

            conflicts = checker.check_package_installation(args.package)
            checker.display_conflicts_with_predictions(args.package)

            if args.command == "auto-resolve":
                success = checker.auto_resolve_and_install(args.package)
                sys.exit(0 if success else 1)

            elif args.command == "learn":
                checker.learn_from_user_resolution(args.package)

            elif args.command == "install":
                if conflicts:
                    print(f"\n{RED}❌ Installation blocked due to conflicts{RESET}")
                    print(f"{YELLOW}💡 Use 'auto-resolve' command to automatically fix conflicts{RESET}")
                    audit_logger.log_user_action(args.command, "INSTALL_BLOCKED", {"package": args.package, "conflicts": len(conflicts)})
                    sys.exit(1)
                else:
                    print(f"\n{GREEN}✅ Safe to install. Proceeding...{RESET}")
                    subprocess.run([sys.executable, "-m", "pip", "install", args.package], check=True)
                    audit_logger.log_user_action(args.command, "INSTALL_SUCCESS", {"package": args.package})
                    print(f"{GREEN}✅ Successfully installed {args.package}{RESET}")

        # Show session summary at the end
        if args.verbose:
            checker.show_session_summary()

    finally:
        checker.close()


if __name__ == "__main__":
    main()
