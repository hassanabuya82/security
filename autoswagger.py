#!/usr/bin/env python3
# Autoswagger - Cale Anderson @ Intruder    
import argparse
import hashlib
import getpass
import json
import math
import os
import re
import sys
import threading
import time
import uuid
from itertools import islice, product as itertools_product
from urllib.parse import quote, unquote, urljoin, urlencode, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from dicttoxml import dicttoxml
import yaml
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from concurrent.futures import ThreadPoolExecutor, as_completed

# Import Presidio for PII detection
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.markup import escape
from rich.table import Table
from rich.logging import RichHandler
import logging

# ------------------------------
# Global Variables for Stats
# ------------------------------
TOTAL_REQUESTS = 0       # Tracks total requests sent by the tool
AUTH_REQUIRED_COUNT = 0  # Endpoints that answered 401/403 (i.e. require auth)
SCAN_START_TIME = 0.0    # Records scan start time (for RPS calculation)
SCAN_END_TIME = 0.0      # Records scan end time (for RPS calculation)

# Initialize Presidio Analyzer with custom recognizers
registry = RecognizerRegistry()

# Initialize file_handler for log data output
file_handler = None

def setup_pii_recognizers():
    """
    Adds custom recognizers for Person, Phone, Email, and Address to the Presidio registry.
    Base scores sit below PII_SCORE_THRESHOLD on purpose: a value only counts as PII
    when the context boost from a matching field name (e.g. 'firstName') lifts it over.
    Patterns are case-sensitive (Presidio's default is case-insensitive, which made
    'not found' look like a person's name).
    """
    flags = re.MULTILINE | re.DOTALL

    # Person: "Jane Doe", "Mary-Ann O'Neil", or a single capitalized word for firstName/lastName fields
    person_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        patterns=[
            Pattern(name="full_name", regex=r"\b[A-Z][a-z'\-]+(?:\s[A-Z][a-z'\-]+){1,3}\b", score=0.4),
            Pattern(name="single_name", regex=r"^[A-Z][a-z'\-]{1,30}$", score=0.3),
        ],
        context=["name", "firstname", "lastname", "fullname", "surname", "givenname", "familyname", "first", "last"],
        global_regex_flags=flags
    )

    # Phone Number
    phone_recognizer = PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[Pattern(name="phone_number", regex=r"(\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})", score=0.4)],
        context=["phone", "mobile", "telephone", "tel", "cell", "fax", "msisdn"],
        global_regex_flags=flags
    )

    # Email Address
    email_recognizer = PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        patterns=[Pattern(name="email", regex=r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", score=0.5)],
        context=["email", "mail"],
        global_regex_flags=flags
    )

    # Address: a house number followed by a street suffix, or (weaker) number + words
    address_recognizer = PatternRecognizer(
        supported_entity="ADDRESS",
        patterns=[
            Pattern(
                name="street_address",
                regex=r"\b\d{1,5}[A-Za-z]?\s+(?:[A-Za-z0-9.'\-]+\s+){0,4}(?i:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl|terrace|close|crescent|square|sq|highway|hwy|parkway|pkwy)\b\.?",
                score=0.5
            ),
            # Capitalized words only, so error text like "404 not found" doesn't qualify
            Pattern(name="number_and_words", regex=r"\b\d{1,5}[A-Za-z]?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b", score=0.3),
        ],
        context=["address", "addr", "street"],
        global_regex_flags=flags
    )

    # Add each recognizer to the registry
    registry.add_recognizer(person_recognizer)
    registry.add_recognizer(phone_recognizer)
    registry.add_recognizer(email_recognizer)
    registry.add_recognizer(address_recognizer)

# Call setup function to prepare custom PII recognizers
setup_pii_recognizers()

# Initialize Presidio context-aware enhancer
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer

context_aware_enhancer = LemmaContextAwareEnhancer(
    context_similarity_factor=0.35,
    min_score_with_context_similarity=0.4
)

# Analyzer engine for detection
analyzer = AnalyzerEngine(
    registry=registry,
    context_aware_enhancer=context_aware_enhancer
)

# Initialize Rich Console for formatted output
# Logs, banner and progress go to stderr; results go to stdout, so
# `autoswagger.py -json ... | jq` receives clean JSON
console = Console(stderr=True)
output_console = Console()

# Suppress warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default request timeout
TIMEOUT = 10

# Upper bound on value combinations tried per endpoint in brute mode
MAX_BRUTE_COMBOS = 50

# Finding severities, lowest to highest
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Retries for throttled/unavailable responses, and the longest Retry-After we'll honor
MAX_RETRIES = 3
MAX_RETRY_DELAY = 60

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"

class RateLimiter:
    """
    A single limiter shared by every worker thread, so -rate caps the tool's total
    request rate rather than each thread's. pause() pushes every thread back at once,
    e.g. when the server answers 429.
    """
    def __init__(self, rate=30):
        self.lock = threading.Lock()
        self.next_time = 0.0
        self.set_rate(rate)

    def set_rate(self, rate):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_time)
            self.next_time = slot + self.interval
        if slot > now:
            time.sleep(slot - now)

    def pause(self, seconds):
        with self.lock:
            self.next_time = max(self.next_time, time.monotonic() + seconds)

rate_limiter = RateLimiter()
request_count_lock = threading.Lock()
thread_local = threading.local()

def get_session():
    """
    Returns this thread's requests.Session (sessions aren't thread-safe, but
    reusing one per thread keeps connections alive across requests).
    """
    session = getattr(thread_local, 'session', None)
    if session is None:
        session = requests.Session()
        session.headers['User-Agent'] = USER_AGENT
        session.verify = False
        thread_local.session = session
    return session

def retry_after_seconds(response, attempt):
    """
    Returns how long to wait before retrying: the Retry-After header (seconds or
    HTTP date) if present, otherwise exponential backoff. Capped at MAX_RETRY_DELAY.
    """
    header = response.headers.get('Retry-After', '').strip()
    delay = None
    if header.isdigit():
        delay = int(header)
    elif header:
        try:
            delay = (parsedate_to_datetime(header) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            delay = None
    if delay is None or delay < 0:
        delay = 2 ** attempt
    return min(delay, MAX_RETRY_DELAY)

class Identity:
    """
    A named set of credentials attached to requests: HTTP headers (which may
    include Authorization and Cookie). The anonymous identity has no headers.
    """
    def __init__(self, name="anonymous", headers=None):
        self.name = name
        self.headers = headers or {}

    @property
    def authenticated(self):
        return bool(self.headers)

    def __repr__(self):
        return f"Identity({self.name!r}, {len(self.headers)} header(s))"

# The identity used for the current scan. Replaced once, before scanning starts,
# so every worker thread reads the same one.
ANONYMOUS = Identity()
active_identity = ANONYMOUS

def set_active_identity(identity):
    global active_identity
    active_identity = identity

def parse_header_arg(raw):
    """
    Parses a 'Name: value' CLI/file header into (name, value). Raises ValueError
    if there is no colon.
    """
    if ':' not in raw:
        raise ValueError(f"header must be in 'Name: value' form, got: {raw!r}")
    name, _, value = raw.partition(':')
    return name.strip(), value.strip()

def http_request(method, url, identity=None, **kwargs):
    """
    Sends a request through the shared rate limiter and this thread's session.
    The active identity's auth headers are attached (per-call headers win on a clash).
    429 and 503 are retried for any method (the server didn't process them);
    502 and 504 only for safe methods. Every attempt counts toward TOTAL_REQUESTS.
    """
    global TOTAL_REQUESTS
    kwargs.setdefault('timeout', TIMEOUT)
    safe_method = method.upper() in ('GET', 'HEAD', 'OPTIONS')

    identity = identity if identity is not None else active_identity
    if identity.headers:
        kwargs['headers'] = {**identity.headers, **(kwargs.get('headers') or {})}

    for attempt in range(MAX_RETRIES + 1):
        rate_limiter.wait()
        with request_count_lock:
            TOTAL_REQUESTS += 1
        response = get_session().request(method, url, **kwargs)

        status = response.status_code
        retryable = status in (429, 503) or (status in (502, 504) and safe_method)
        if not retryable or attempt == MAX_RETRIES:
            return response
        # Slow every thread down, not just this one
        rate_limiter.pause(retry_after_seconds(response, attempt))
    return response

# Paths for detecting swagger/openapi specs in UI or direct spec endpoints
SWAGGER_UI_PATHS = sorted({
    "/", "/apidocs/", "/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html",
    "/swagger/swagger-ui.html", "/api/swagger-ui.html", "/api_docs", "/api/index.html",
    "/api/doc", "/api/docs/", "/api/swagger/index.html", "/api/swagger/swagger-ui.html",
    "/api/swagger-ui/api-docs", "/api/api-docs", "/api/apidocs", "/api/swagger",
    "/api/swagger/static/index.html", "/api/swagger-resources",
    "/api/swagger-resources/restservices/v2/api-docs", "/api/__swagger__/", "/api/_swagger_/",
    "/docu", "/docs", "/swagger", "/api-doc", "/doc/",
    "/webjars/swagger-ui/index.html", "/3.0.0/swagger-ui.html",
    "/MobiControl/api/docs/index/index.html", "/Swagger", "/Swagger/", "/Swagger/index.html",
    "/V2/api-docs/ui", "/admin/swagger-ui/index.html", "/api-doc/", "/api-docs/",
    "/api-docs/ui/", "/api-docs/v1/index.html", "/api-documentation/index.html",
    "/api/", "/api/api-docs", "/api/api-docs/index.html", "/api/api/",
    "/api/apidocs", "/api/config", "/api/doc", "/api/doc/", "/api/spec/", "/spec/",
    "/swagger-ui/", "/swagger-ui/index.html",
})

DIRECT_SPEC_PATHS = sorted({
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/v1/swagger.json",
    "/v1/swagger.yaml", "/v1/swagger.yml", "/openapi.json",
    "/openapi.yaml", "/openapi.yml", "/api/openapi.json",
    "/api/openapi.yaml", "/api/openapi.yml", "/docs/swagger.json",
    "/docs/swagger.yaml", "/docs/openapi.json", "/docs/openapi.yaml",
    "/api-docs/swagger.json", "/api-docs/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
    "/rest/swagger.json", "/rest/swagger.yaml", "/rest-api/swagger.json",
    "/swagger/v1/docs.json", "/api/swagger/docs.json",
    "/swagger/docs/v1.json", "/swagger/swagger.json", "/swagger/swagger.yaml",
    "/api-doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
    "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
    "/api/swagger_doc.json", "/v2/swagger.json", "/v2/swagger.yaml",
    "/v3/swagger.json", "/v3/swagger.yaml", "/openapi2.json",
    "/openapi2.yaml", "/openapi2.yml", "/api/v3/openapi.json",
    "/api/v3/openapi.yaml", "/api/v3/openapi.yml", "/spec/swagger.json",
    "/spec/swagger.yaml", "/spec/openapi.json", "/spec/openapi.yaml",
    "/api-docs/swagger-ui.json", "/api-docs/swagger-ui.yaml",
    "/api-docs/openapi.json", "/api-docs/openapi.yaml",
    "/swagger-ui.json", "/swagger-ui.yaml",
    # Extensionless specs: Springfox (/v2/api-docs), springdoc (/v3/api-docs) and others
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/v2/api-docs", "/api/v3/api-docs",
    "/v3/api-docs/swagger-config", "/swagger-resources", "/openapi", "/api/openapi",
    "/swagger/v2/swagger.json", "/api/v1/openapi.json", "/api/v1/swagger.json",
    "/openapi/v1.json", "/api/docs/openapi.json"
})

# Regex patterns for secrets (similar to TruffleHog)
TRUFFLEHOG_REGEXES = {
    "Slack Token": r"(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": r"\bAKIA[0-9A-Z]{16}\b",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": r"da2-[a-z0-9]{26}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"(?i:facebook).{0,20}?['\"]([0-9a-f]{32})['\"]",
    "GitHub": r"(?i:github).{0,20}?['\"]([0-9a-zA-Z]{35,40})['\"]",
    "GitHub Token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
    "Generic API Key": r"(?i:api[_-]?key)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{32,45})['\"]",
    "Generic Secret": r"(?i:secret)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{32,45})['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Password in URL": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}['\"\s]",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Telegram Bot API Key": r"\b[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}\b",
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "Twitter Access Token": r"(?i:twitter).{0,20}?\b([1-9][0-9]+-[0-9a-zA-Z]{40})\b",
    "Twitter OAuth": r"(?i:twitter).{0,20}?['\"]([0-9a-zA-Z]{35,44})['\"]"
}

# Compile the regexes for performance
COMPILED_TRUFFLEHOG_REGEXES = {name: re.compile(pattern) for name, pattern in TRUFFLEHOG_REGEXES.items()}

# Patterns loose enough to also match placeholders or ordinary IDs; their matches
# must look random (Shannon entropy per character) to count as a secret
ENTROPY_CHECKED_SECRETS = {
    "Facebook OAuth", "GitHub", "Generic API Key", "Generic Secret",
    "Twilio API Key", "Twitter OAuth",
}
MIN_SECRET_ENTROPY = 3.0

# Debug info patterns: concrete signs of stack traces, debug pages or leaked environment
# config. Reported separately from secrets as a low-severity note. Bare words like
# 'ERROR' or 'DEBUG' are deliberately not matched; they appear in ordinary error bodies.
DEBUG_INFO_PATTERNS = {
    "Python stack trace": r"Traceback \(most recent call last\)",
    "Java stack trace": r"\bat [\w$.]+\([\w$]+\.java:\d+\)",
    ".NET stack trace": r"\bat [\w.`<>]+\([^)\n]*\) in [^\n]+?:line \d+",
    "Node.js stack trace": r"\bat [^\n()]+ \((?:/|[A-Za-z]:\\)[^)\n]+\.[cm]?js:\d+:\d+\)",
    "PHP error": r"(?:Fatal error|Parse error|Warning)</b>?: .{0,200}? on line <b>?\d+",
    "Framework debug page": r"Werkzeug Debugger|Whoops! There was an error|Django Version:|Laravel Debugbar",
    "Environment variable dump": r"\b(?:AWS|AZURE)_[A-Z0-9_]{3,}[\"']?\s*[:=]",
}
COMPILED_DEBUG_INFO_PATTERNS = {name: re.compile(p) for name, p in DEBUG_INFO_PATTERNS.items()}

# Default test values for parameters by type
TEST_VALUES = {
    "integer": [1, 2, 100, -1, 0, 999, 123456],
    "string": [
        "1", "test", "example", "1234", "none", "admin", "guest", "user@email.com",
        "550e8400-e29b-41d4-a716-446655440000",
        "a8098c1a-f86e-11da-bd1a-00112444be1e"
    ],
    "boolean": [True, False],
    "number": [1, 0, 100, 1000, 0.1],
    "base64": ["MQ==", "dXNlcjE=", "YWRtaW4xMjM=", "c2FtcGxlVXNlcg=="],
    "default": ["1", "test", "123", "True","true","550e8400-e29b-41d4-a716-446655440000", "*", "All"]
}

# Lock for thread-safe operations
lock = threading.Lock()

# Initialize logger with RichHandler
logger = logging.getLogger("autoswagger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")

# Set to track hosts where no valid swagger was found
bad_hosts = set()

def get_timestamp():
    """
    Returns current timestamp in the format [HH:MM:SS].
    Used for logging messages with a consistent time prefix.
    """
    return time.strftime("[%H:%M:%S]")

def log(message, level="INFO"):
    """
    Logs a message with a given level to both the Rich console and the optional file_handler.

    :param message: String message to log
    :param level: Logging level ('INFO', 'DEBUG', 'WARNING', 'CRITICAL', 'SUCCESS')
    """
    global file_handler
    timestamp = get_timestamp()
    levels = {
        "INFO": "[green][INFO][/green]",
        "DEBUG": "[cyan][DEBUG][/cyan]",
        "WARNING": "[yellow][WARNING][/yellow]",
        "CRITICAL": "[red][CRITICAL][/red]",
        "SUCCESS": "[bold green][SUCCESS][/bold green]"
    }
    level_prefix = levels.get(level, f"[{level}]")
    formatted_message = f"{timestamp} {level_prefix} {message}"
    console.print(formatted_message, highlight=False)
    if file_handler and level == "DEBUG":
        logger.debug(message)
    elif file_handler and level in ["INFO", "WARNING", "CRITICAL", "SUCCESS"]:
        logger.info(message)

def print_banner():
    """
    Prints the ASCII banner for Autoswagger with intruder.io link in yellow.
    Called if not in product mode, to show the standard header.
    """
    banner = f"""[white]
      /   | __  __/ /_____  ______      ______ _____ _____ ____  _____
     / /| |/ / / / __/ __ \\/ ___/ | /| / / __ `/ __ `/ __ `/ _ \\/ ___/
    / ___ / /_/ / /_/ /_/ (__  )| |/ |/ / /_/ / /_/ / /_/ /  __/ /
    /_/  |_\\__,_/\\__/\\____/____/ |__/|__/_\\__,_/\\__, /\\__, /\\___/_/
                                              /____//____/[/white]
                              [yellow]https://intruder.io[/yellow]
                          Find unauthenticated endpoints
    """
    console.print(banner)

def generate_parameter_values(param_type, enum=None):
    """
    Returns a list of test values for a given parameter type.
    If an enum list is provided, uses that instead of defaults.
    """
    if enum:
        return enum
    return TEST_VALUES.get(param_type, TEST_VALUES["default"])

def schema_example(schema):
    """
    Returns the example value declared by a schema or Swagger 2 parameter
    ('example', OAS 3.1 'examples' list, 'x-example', then 'default'), or None.
    """
    if not isinstance(schema, dict):
        return None
    if schema.get('example') is not None:
        return schema['example']
    examples = schema.get('examples')
    if isinstance(examples, list) and examples:
        return examples[0]
    if schema.get('x-example') is not None:
        return schema['x-example']
    return schema.get('default')

def param_example(param):
    """
    Returns the example declared on an OpenAPI 3 parameter object itself
    ('example', or the first entry of the 'examples' map), or None.
    """
    if param.get('example') is not None:
        return param['example']
    examples = param.get('examples')
    if isinstance(examples, dict):
        for ex in examples.values():
            if isinstance(ex, dict) and ex.get('value') is not None:
                return ex['value']
    return None

def param_schema(param):
    """
    Returns the schema describing a parameter's value. OpenAPI 3 nests it under
    'schema'; Swagger 2 puts 'type', 'enum', 'default' etc. on the parameter itself.
    """
    schema = param.get('schema')
    return schema if isinstance(schema, dict) else param

def values_for_schema(schema, example=None):
    """
    Returns test values for a schema, with the spec's own example/default first
    (a real-looking value is far more likely to return data than a generic one).
    """
    if example is None:
        example = schema_example(schema)
    values = generate_parameter_values(schema.get('type', 'string'), schema.get('enum'))
    if example is None or isinstance(example, (dict, list)):
        return values
    return [example] + [v for v in values if v != example]

def param_values(param):
    """
    Returns test values for a path/query parameter, using its declared examples first.
    """
    return values_for_schema(param_schema(param), param_example(param))

def build_nested_object(schema, value_index=0):
    """
    Recursively constructs a nested object (dict) for complex schemas.
    Handles properties, arrays, and composite references (oneOf, anyOf, allOf).
    Object or array properties with a declared example use that example as-is.
    """
    obj = {}
    for key, prop in schema.get('properties', {}).items():
        if '$ref' in prop:
            continue
        example = schema_example(prop)
        if isinstance(example, (dict, list)):
            obj[key] = example
        elif 'oneOf' in prop or 'anyOf' in prop or 'allOf' in prop:
            obj[key] = handle_composite_schemas(prop, value_index)
        elif prop.get('type') == 'object':
            obj[key] = build_nested_object(prop, value_index)
        elif prop.get('type') == 'array':
            obj[key] = [build_array_item(prop.get('items', {}), value_index)]
        else:
            values = values_for_schema(prop)
            obj[key] = values[value_index % len(values)]
    return obj

def handle_composite_schemas(schema, value_index=0):
    """
    Handles composite schema definitions like oneOf, anyOf, and allOf.
    Calls build_nested_object recursively on the chosen sub-schema or the combined properties.
    """
    if 'oneOf' in schema:
        return build_nested_object(schema['oneOf'][value_index % len(schema['oneOf'])], value_index)
    elif 'anyOf' in schema:
        return build_nested_object(schema['anyOf'][value_index % len(schema['anyOf'])], value_index)
    elif 'allOf' in schema:
        combined_schema = {}
        for sub_schema in schema['allOf']:
            combined_schema.update(sub_schema.get('properties', {}))
        return build_nested_object({'properties': combined_schema}, value_index)
    return build_nested_object(schema, value_index)

def build_array_item(item_schema, value_index=0):
    """
    Builds an array item from the given schema.
    If the schema is an object or contains properties, delegates to build_nested_object.
    Otherwise chooses from test values by type.
    """
    example = schema_example(item_schema)
    if isinstance(example, (dict, list)):
        return example
    if 'properties' in item_schema or item_schema.get('type') == 'object':
        return build_nested_object(item_schema, value_index)
    else:
        values = values_for_schema(item_schema)
        return values[value_index % len(values)]

def build_file_upload_body(schema, content_type, value_index=0):
    """
    Builds a simple file upload body for multipart/form-data.
    Returns a dict with a file-like tuple if content_type is multipart/form-data.
    """
    if content_type == 'multipart/form-data':
        return {'file': ('test.txt', b'This is a test file')}
    return None

def build_request_body(schema, content_type, value_index=0):
    """
    Builds a request body based on the schema and specified content type.
    Supports JSON, XML, form-encoded, plain text, octet-stream, and multipart.
    """
    if not schema:
        return None

    example = schema_example(schema)
    if isinstance(example, (dict, list)):
        body = example
    elif 'oneOf' in schema or 'anyOf' in schema or 'allOf' in schema:
        body = handle_composite_schemas(schema, value_index)
    elif schema.get('type') == 'array':
        item_schema = schema.get('items', {})
        body = [build_array_item(item_schema, value_index)]
    elif schema.get('type') == 'object':
        body = build_nested_object(schema, value_index)
    else:
        values = values_for_schema(schema)
        body = values[value_index % len(values)]

    if content_type == 'application/x-www-form-urlencoded':
        return urlencode(body)
    elif content_type == 'application/xml':
        return dicttoxml(body).decode()
    elif content_type == 'application/json':
        return json.dumps(body)
    elif content_type == 'text/plain':
        return str(body)
    elif content_type == 'application/octet-stream':
        return b'\x00\x01\x02'
    elif content_type == 'multipart/form-data':
        return build_file_upload_body(schema, content_type, value_index)
    return json.dumps(body)

def substitute_path_parameters(path, parameters, value_mapping):
    """
    Replaces path parameter placeholders (e.g. {id}, :id, <id>) with generated values.
    """
    for param in parameters:
        if param.get('in') == 'path':
            param_name = param.get('name')
            value = value_mapping.get(param_name)
            if value is not None:
                path = re.sub(rf'{{{param_name}}}|:{param_name}|<{param_name}>', str(value), path)
    return path

def generate_query_string(parameters, value_mapping):
    """
    Creates a query string (e.g. ?key=value) for parameters that are in the query location.
    """
    query_params = {}
    for param in parameters:
        if param.get('in') == 'query':
            param_name = param.get('name')
            value = value_mapping.get(param_name)
            if value is not None:
                query_params[param_name] = value
    return urlencode(query_params)

def shannon_entropy(value):
    """
    Returns the Shannon entropy of a string in bits per character
    (random hex is ~4, random base62 ~5, 'xxxxxxxx' is 0).
    """
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum(c / length * math.log2(c / length) for c in counts.values())

def detect_sensitive_info(content):
    """
    Searches the response content for known secret patterns (TruffleHog).
    Returns a dict of matches if found, along with the regex patterns used.
    """
    sensitive_info = {}
    regex_patterns = {}

    for name, pattern in COMPILED_TRUFFLEHOG_REGEXES.items():
        matches = []
        for m in pattern.finditer(content):
            # Patterns with a capture group mark the token itself; record just that
            value = m.group(1) if pattern.groups else m.group(0)
            if name in ENTROPY_CHECKED_SECRETS and shannon_entropy(value) < MIN_SECRET_ENTROPY:
                continue
            if value not in matches:
                matches.append(value)
        if matches:
            sensitive_info.setdefault(name, []).extend(matches)
            regex_patterns[name] = pattern.pattern

    return sensitive_info if sensitive_info else None, regex_patterns

def detect_debug_info(content):
    """
    Searches the response content for stack traces, debug pages and environment dumps.
    Returns {name: [up to 2 matched snippets]} or None.
    """
    found = {}
    for name, pattern in COMPILED_DEBUG_INFO_PATTERNS.items():
        snippets = []
        for match in pattern.finditer(content):
            snippet = match.group(0).strip()
            if snippet not in snippets:
                snippets.append(snippet[:200])
            if len(snippets) >= 2:
                break
        if snippets:
            found[name] = snippets
    return found or None

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ADDRESS"]

# Presidio score a value must reach; only reachable with a field-name context boost
PII_SCORE_THRESHOLD = 0.6

# Caps the Presidio calls per response, so huge JSON bodies don't stall the scan
MAX_PII_VALUES_PER_RESPONSE = 1000

# Field-name tokens that point at each kind of PII. Matching is on whole tokens
# ('hostName' -> ['host', 'name']), so 'hotel' no longer matches 'tel', etc.
EMAIL_KEY_TOKENS = {"email", "mail", "emailaddress"}
PHONE_KEY_TOKENS = {"phone", "mobile", "telephone", "tel", "cell", "cellphone", "fax", "msisdn", "phonenumber"}
ADDRESS_KEY_TOKENS = {"address", "addr", "street", "streetaddress", "addressline"}
# Tokens that make an 'address' field technical rather than postal
NON_POSTAL_ADDRESS_TOKENS = {
    "ip", "ipv4", "ipv6", "mac", "wallet", "server", "remote", "host", "bind", "listen",
    "web", "url", "contract", "node", "peer", "proxy", "gateway", "local", "public",
    "private", "network", "net", "broadcast", "memory", "base", "return", "bitcoin", "eth",
}
PERSON_KEYS = {
    "firstname", "lastname", "fullname", "surname", "givenname", "familyname",
    "middlename", "displayname", "forename", "maidenname",
}
PERSON_NAME_QUALIFIERS = {
    "first", "last", "full", "given", "family", "middle", "display", "contact", "customer",
    "owner", "person", "holder", "account", "patient", "employee", "member", "billing",
    "shipping", "legal", "real", "sur", "fore",
}

def key_tokens(key):
    """
    Splits a field name into lowercase tokens: 'customerEmail' -> ['customer', 'email'],
    'phone_number' -> ['phone', 'number'], 'Address-Line1' -> ['address', 'line1'].
    """
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', str(key))
    return [t for t in re.split(r'[^A-Za-z0-9]+', spaced.lower()) if t]

def classify_pii_key(key):
    """
    Returns (entity_type, weak) for a field name that suggests PII, or (None, False).
    A bare 'name' is weak: it is just as often a product or file name, so it only
    counts when the same record also has an email/phone/address field.
    """
    tokens = key_tokens(key)
    if not tokens:
        return None, False
    token_set = set(tokens)
    compact = ''.join(tokens)

    if token_set & EMAIL_KEY_TOKENS:
        return "EMAIL_ADDRESS", False
    if token_set & PHONE_KEY_TOKENS:
        return "PHONE_NUMBER", False
    if token_set & ADDRESS_KEY_TOKENS and not token_set & NON_POSTAL_ADDRESS_TOKENS:
        return "ADDRESS", False
    if compact in PERSON_KEYS or (
            len(tokens) >= 2 and tokens[-1] == "name" and tokens[-2] in PERSON_NAME_QUALIFIERS):
        return "PERSON", False
    if compact == "name":
        return "PERSON", True
    return None, False

def pii_keys_to_check(keys):
    """
    Maps each PII-suggestive key in one record (JSON object, CSV header or text body)
    to its entity type, dropping weak keys when no strong PII key sits beside them.
    """
    classified = {k: classify_pii_key(k) for k in keys}
    has_strong = any(entity and not weak for entity, weak in classified.values())
    return {k: entity for k, (entity, weak) in classified.items() if entity and (has_strong or not weak)}

def record_pii(text, entity, key, pii_data):
    """
    Runs Presidio on a single value, looking only for the entity its field name implies,
    and merges any detections into pii_data.
    """
    tokens = key_tokens(key)
    pres_res = analyzer.analyze(
        text=text, entities=[entity], language='en',
        context=tokens + [''.join(tokens)], score_threshold=PII_SCORE_THRESHOLD
    )
    for ent in pres_res:
        value = text[ent.start:ent.end]
        if entity == "PHONE_NUMBER" and not 7 <= sum(ch.isdigit() for ch in value) <= 15:
            continue
        pii_data.setdefault(ent.entity_type, {'values': set(), 'detection_methods': set()})
        pii_data[ent.entity_type]['values'].add(value)
        pii_data[ent.entity_type]['detection_methods'].add('context')

def walk_json_for_pii(node, pii_data, budget, depth=0):
    """
    Recursively walks parsed JSON, analyzing scalar values whose key looks PII-related
    (judged per object, so a bare 'name' counts only next to an email/phone/address field).
    budget is a one-element list holding the remaining number of values to analyze.
    """
    if depth > 50 or budget[0] <= 0:
        return
    if isinstance(node, dict):
        pii_keys = pii_keys_to_check(node.keys())
        for key, value in node.items():
            if budget[0] <= 0:
                return
            if isinstance(value, (dict, list)):
                walk_json_for_pii(value, pii_data, budget, depth + 1)
            elif isinstance(value, (str, int, float)) and not isinstance(value, bool) and key in pii_keys:
                text = str(value).strip()
                if text:
                    budget[0] -= 1
                    record_pii(text, pii_keys[key], key, pii_data)
    elif isinstance(node, list):
        for item in node:
            if budget[0] <= 0:
                return
            if isinstance(item, (dict, list)):
                walk_json_for_pii(item, pii_data, budget, depth + 1)

def detect_pii(content_text):
    """
    Detects PII in a response body. JSON bodies are parsed and walked key by key,
    so minified (single-line) JSON is fully covered. Other bodies fall back to
    CSV-row and naive "key: value" line scanning.
    Returns a dict of {entity_type: {'values': set, 'detection_methods': set}}.
    """
    pii_data = {}
    budget = [MAX_PII_VALUES_PER_RESPONSE]

    stripped = content_text.lstrip()
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            parsed = json.loads(content_text)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            walk_json_for_pii(parsed, pii_data, budget)
            return pii_data

    lines = content_text.splitlines()

    # Simple CSV detection: check first line for multiple commas
    csv_header = []
    if lines:
        columns = lines[0].split(',')
        if len(columns) >= 3:
            csv_header = [col.strip().lower() for col in columns]

    # If CSV header recognized, parse subsequent lines with the same number of columns
    if csv_header:
        csv_pii_keys = pii_keys_to_check(csv_header)
        for line in lines[1:]:
            row_cols = line.split(',')
            if len(row_cols) != len(csv_header):
                continue
            for col_name, cell in zip(csv_header, row_cols):
                if budget[0] <= 0:
                    return pii_data
                cell_value = cell.strip()
                if cell_value and col_name in csv_pii_keys:
                    budget[0] -= 1
                    record_pii(cell_value, csv_pii_keys[col_name], col_name, pii_data)

    # Also do a naive "key: value" detection line by line
    pairs = []
    for line in lines:
        if ':' in line:
            key_part, val_part = line.split(':', 1)
            pairs.append((key_part.strip(), val_part.strip()))
    line_pii_keys = pii_keys_to_check(k for k, _ in pairs)
    for key_part, val_part in pairs:
        if budget[0] <= 0:
            break
        if val_part and key_part in line_pii_keys:
            budget[0] -= 1
            record_pii(val_part, line_pii_keys[key_part], key_part, pii_data)

    return pii_data

# Thresholds for flagging a response as a large data exposure
LARGE_RESPONSE_ITEMS = 100
LARGE_RESPONSE_BYTES = 100000

def count_response_items(content):
    """
    Returns how many records a response holds: the length of the largest JSON array
    within the top two levels (so {"data": [...]} counts its list), the key count of a
    flat JSON object, or the element count of an XML document. 0 if not parseable.
    """
    stripped = content.strip()
    try:
        if stripped.startswith('{') or stripped.startswith('['):
            data = json.loads(stripped)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                nested = [len(v) for v in data.values() if isinstance(v, list)]
                return max(nested + [len(data)])
        elif stripped.startswith('<'):
            return sum(1 for _ in ET.fromstring(stripped).iter())
    except (ValueError, ET.ParseError):
        pass
    return 0

PII_LABELS = {"PERSON": "Name", "EMAIL_ADDRESS": "Email", "PHONE_NUMBER": "Phone", "ADDRESS": "Address"}

def redact(value):
    """
    Masks a sample for display: 'jane@acme.io' -> 'j***@acme.io', 'AKIA1234ABCD' -> 'AK***CD'.
    """
    value = str(value)
    if '@' in value:
        local, _, domain = value.partition('@')
        return f"{local[:1]}***@{domain}"
    if len(value) <= 4:
        return f"{value[:1]}***"
    keep = 2 if len(value) < 16 else 4
    return f"{value[:keep]}***{value[-keep:]}"

def assess_findings(status_code, pii_data, secrets, debug_info, is_large, item_count, content_length):
    """
    Builds human-readable findings and the overall severity of a response:
    critical = secret, high = PII, medium = large data dump, low = debug info, info = none.
    Secrets and debug output count at any status; PII and size only on a 2xx.
    """
    findings = []
    severity = "info"
    ok = 200 <= status_code < 300

    def raise_to(level):
        nonlocal severity
        if SEVERITY_RANK[level] > SEVERITY_RANK[severity]:
            severity = level

    for name, values in (secrets or {}).items():
        unique = list(dict.fromkeys(values))
        findings.append(f"Secret: {name} ×{len(unique)} ({redact(unique[0])})")
        raise_to("critical")
    if ok:
        for entity, data in (pii_data or {}).items():
            values = sorted(data['values'])
            findings.append(f"PII: {PII_LABELS.get(entity, entity)} ×{len(values)} ({redact(values[0])})")
            raise_to("high")
        if is_large:
            size = f"{item_count:,} items" if item_count >= LARGE_RESPONSE_ITEMS else f"{content_length:,} bytes"
            findings.append(f"Large response: {size}")
            raise_to("medium")
    for name in (debug_info or {}):
        findings.append(f"Debug info: {name}")
        raise_to("low")
    return severity, findings

def body_fingerprint(content, requested_path):
    """
    Hashes a response body after removing the requested path from it, so catch-all
    pages that echo the URL ("Cannot GET /foo") still hash the same for every path.
    """
    text = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else content
    if requested_path and requested_path != '/':
        text = text.replace(requested_path, '').replace(quote(requested_path), '')
    return hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()

def short_content_type(response):
    """
    Returns the bare media type of a response, e.g. 'application/json'.
    """
    return response.headers.get('Content-Type', '').split(';')[0].strip().lower()

def take_baselines(base_url, base_path, methods, verbose=False):
    """
    Requests random, certainly-nonexistent paths (under the base path and at the root)
    to learn what this server returns for unknown routes. SPAs and catch-all routes
    answer these with a 200, which would otherwise make every endpoint look exposed.
    Returns a list of {'method', 'status_code', 'content_type', 'content_length', 'body_hash'}.
    """
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    prefixes = {'', base_path.rstrip('/')}

    baselines = []
    for method in sorted(methods):
        for prefix in sorted(prefixes):
            path = f"{prefix}/autoswagger-{uuid.uuid4().hex[:12]}"
            try:
                resp = http_request(method, root + path, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                if verbose:
                    log(f"Baseline request {method} {root + path} failed: {e}", level="DEBUG")
                continue
            baselines.append({
                'method': method,
                'status_code': resp.status_code,
                'content_type': short_content_type(resp),
                'content_length': len(resp.content),
                'body_hash': body_fingerprint(resp.content, path),
            })
            if verbose:
                log(f"Baseline {method} {path}: {resp.status_code}, {len(resp.content)} bytes", level="DEBUG")
    return baselines

def matches_baseline(result, baselines):
    """
    Returns True if a result looks like the server's response to an unknown route:
    same status and identical (path-normalized) body, or, for HTML pages whose markup
    may carry per-request nonces, the same status and a near-identical length.
    """
    for b in baselines:
        if b['method'] != result['method'] or b['status_code'] != result['status_code']:
            continue
        if b['body_hash'] == result['_body_hash']:
            return True
        if ('html' in b['content_type'] and 'html' in result['content_type']
                and abs(b['content_length'] - result['content_length']) <= max(64, b['content_length'] * 0.02)):
            return True
    return False

def declared_response_types(spec, details):
    """
    Returns the media types an operation says it responds with: OpenAPI 3
    'responses.*.content' keys, or Swagger 2 'produces' (operation or global).
    """
    types = set()
    for resp in (details.get('responses') or {}).values():
        if isinstance(resp, dict):
            types.update(k.lower() for k in (resp.get('content') or {}))
    produces = details.get('produces') or spec.get('produces') or []
    types.update(p.lower() for p in produces if isinstance(p, str))
    return types

def required_auth_schemes(spec, details):
    """
    Returns the security schemes the spec says an operation requires (e.g.
    ['bearerAuth']), or [] if it is public. The operation's 'security' overrides the
    global one; an empty requirement ({}) in the list means auth is optional.
    """
    security = details.get('security', spec.get('security'))
    if not isinstance(security, list) or not security:
        return []
    if any(not req for req in security):
        return []
    schemes = []
    for req in security:
        if isinstance(req, dict):
            schemes.extend(name for name in req if name not in schemes)
    return schemes

# Path segments and scope/role words that mark an endpoint as privileged
ADMIN_PATH_HINTS = {
    "admin", "admins", "administrator", "administration", "superuser", "superadmin",
    "root", "manage", "management", "manager", "internal", "console", "backoffice",
    "sysadmin", "privileged", "moderator", "staff", "operator",
}
ADMIN_SCOPE_HINTS = ("admin", "superuser", "manage", "write:admin", "root", "sudo", "elevated")

def privileged_reason(path_template, spec, details):
    """
    Returns a short reason if an endpoint looks privileged (admin-only), else None.
    Two signals: an admin-like path segment, or a security scope/role that implies
    elevated access.
    """
    segments = {seg.lower() for seg in re.split(r'[^A-Za-z0-9]+', path_template) if seg}
    hit = segments & ADMIN_PATH_HINTS
    if hit:
        return f"admin path segment '{sorted(hit)[0]}'"

    security = details.get('security', spec.get('security'))
    if isinstance(security, list):
        for requirement in security:
            if not isinstance(requirement, dict):
                continue
            for scopes in requirement.values():
                for scope in scopes or []:
                    if isinstance(scope, str) and any(h in scope.lower() for h in ADMIN_SCOPE_HINTS):
                        return f"privileged scope '{scope}'"
    return None

def apply_auth_finding(result, auth_schemes):
    """
    Records what the spec declares about auth on a result, and flags a 2xx from an
    endpoint the spec says requires auth: the unauthenticated request should have
    been refused, so access control is likely not enforced.
    """
    result['auth_required_by_spec'] = auth_schemes
    if auth_schemes and 200 <= result['status_code'] < 300:
        result['findings'].insert(0, f"Auth not enforced: spec requires {', '.join(auth_schemes)}")
        if SEVERITY_RANK[result['severity']] < SEVERITY_RANK['medium']:
            result['severity'] = 'medium'
        result['interesting_response'] = True

def false_positive_reason(result, baselines, expected_types):
    """
    Explains why a 2xx result is not a real exposure (None if it looks genuine):
    it matches the unknown-route baseline, or it's an HTML page from an endpoint
    whose spec only declares non-HTML responses (typically an SPA fallback page).
    """
    if not 200 <= result['status_code'] < 300:
        return None
    if matches_baseline(result, baselines):
        return "matches the response for a random nonexistent path"
    if ('html' in result['content_type'] and expected_types
            and not any('html' in t or t == '*/*' for t in expected_types)):
        return "returned HTML but the spec declares " + ", ".join(sorted(expected_types))
    return None

def test_parameter_values(method, base_url_no_path, full_path, parameters, request_body, content_type, include_all, verbose, brute=False):
    """
    Tests parameter values for a given method/endpoint.
    If brute is false, only a single default set is tested.
    If brute is true, tries up to MAX_BRUTE_COMBOS value combinations (spec examples
    first) and returns the best response, preferring 2xx over 4xx/5xx.
    """
    value_mapping = {}

    # Collect a default mapping from the parameter schema
    for param in parameters:
        if param.get('in') not in ['path', 'query']:
            continue
        value_mapping[param.get('name')] = param_values(param)[0]

    # Default mode: one request
    if not brute:
        response = send_request(
            method, base_url_no_path, full_path, parameters,
            value_mapping, request_body, content_type, include_all, verbose
        )
        return [response] if response else []

    # Brute mode: try value combinations and keep the best response. A 4xx is not a
    # success; keep going until a 2xx turns up (or the combination budget runs out).
    names = []
    candidates = []
    all_typed = True
    for param in parameters:
        if param.get('in') not in ['path', 'query']:
            continue
        schema = param_schema(param)
        names.append(param.get('name'))
        # Treat the parameter as typed if the spec gives a type, enum or example
        if schema.get('type') or schema.get('enum') or param_example(param) is not None or schema_example(schema) is not None:
            candidates.append(param_values(param))
        else:
            # Unknown type: try values of every basic type
            all_typed = False
            fallback = []
            for test_type in ['integer', 'string', 'boolean', 'number']:
                fallback.extend(v for v in generate_parameter_values(test_type) if v not in fallback)
            candidates.append(fallback)

    best_response = None
    for combo in islice(itertools_product(*candidates), MAX_BRUTE_COMBOS):
        resp = send_request(
            method, base_url_no_path, full_path, parameters,
            dict(zip(names, combo)), request_body, content_type, include_all, verbose
        )
        if resp and (best_response is None or response_rank(resp) > response_rank(best_response)):
            best_response = resp
        # With known types the first 2xx is good enough; with guessed types keep
        # looking for the combination that returns the most data
        if all_typed and best_response and 200 <= best_response['status_code'] < 300:
            break
    return [best_response] if best_response else []

SEVERITY_STYLES = {
    "critical": "bold white on red", "high": "bold red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}

def sort_results(results):
    """
    Orders results most severe first, then by response size.
    """
    return sorted(results, key=lambda r: (-SEVERITY_RANK[r['severity']], -r['content_length']))

def response_rank(result):
    """
    Orders results for picking the best one per endpoint: a 2xx beats anything else,
    then higher severity, then a larger body.
    """
    return (
        200 <= result['status_code'] < 300,
        SEVERITY_RANK.get(result.get('severity'), 0),
        result['content_length'],
    )

def send_request(method, base_url_no_path, full_path, parameters, value_mapping, request_body, content_type, include_all, verbose):
    """
    Sends a request to the computed endpoint through the shared rate limiter.
    Decodes the response, checks for secrets, PII (via line-based CSV and key:value scanning),
    returns a dictionary summarizing the result (status code, content length, PII, etc.)
    Skips 401 and 403 responses by default.
    """
    substituted_path = substitute_path_parameters(full_path, parameters, value_mapping)
    query_string = generate_query_string(parameters, value_mapping)

    if not substituted_path.startswith('/'):
        substituted_path = '/' + substituted_path

    parsed_path = urlparse(substituted_path)
    if parsed_path.scheme in ['http', 'https']:
        full_url = substituted_path
    else:
        if query_string:
            full_url = f"{urljoin(base_url_no_path, substituted_path)}?{query_string}"
        else:
            full_url = urljoin(base_url_no_path, substituted_path)

    headers = {'Content-Type': content_type} if content_type else {}
    data = request_body if method.upper() in ['POST', 'PUT', 'PATCH'] else None

    try:
        response = http_request(
            method, full_url, headers=headers, data=data, allow_redirects=False
        )
        status_code = response.status_code

        # Skip 401 and 403 by design, but count them: they mark endpoints that
        # require authentication, which drives the "rerun with --login" hint
        if status_code in [401, 403]:
            global AUTH_REQUIRED_COUNT
            with request_count_lock:
                AUTH_REQUIRED_COUNT += 1
            if verbose:
                log(f"Skipping endpoint {method.upper()} {full_url} due to status code {status_code}", level="INFO")
            return None

        content_length = len(response.content)
        try:
            content_text = response.content.decode('utf-8', errors='ignore')
        except Exception:
            content_text = ''

        # Detect secrets in entire content
        sensitive_info, regex_patterns = detect_sensitive_info(content_text)

        pii_data = detect_pii(content_text)
        pii_detected = bool(pii_data)
        interesting_response = False
        item_count = count_response_items(content_text)
        is_large = item_count >= LARGE_RESPONSE_ITEMS or content_length > LARGE_RESPONSE_BYTES
        debug_info = detect_debug_info(content_text)

        # Readable findings (counts + one redacted sample) and an overall severity
        severity, findings = assess_findings(status_code, pii_data, sensitive_info, debug_info,
                                             is_large, item_count, content_length)

        if pii_data:
            for entity_type in pii_data:
                pii_data[entity_type]['values'] = list(pii_data[entity_type]['values'])[:2]
                pii_data[entity_type]['detection_methods'] = list(pii_data[entity_type]['detection_methods'])

        # Mark interesting if 200 (or 404 if include_all) plus big or has PII
        if status_code == 200 or (include_all and status_code == 404):
            if is_large:
                interesting_response = True
            if pii_detected:
                interesting_response = True

        result = {
            "method": method.upper(),
            "url": full_url,
            "path_template": full_path,
            "identity": active_identity.name,
            "body": data if data else "",
            "status_code": status_code,
            "content_type": short_content_type(response),
            "content_length": content_length,
            "item_count": item_count,
            "severity": severity,
            "findings": findings,
            # Internal: used to compare against the unknown-route baseline, removed before output
            "_body_hash": body_fingerprint(response.content, urlparse(full_url).path),
            "pii_detected": pii_detected,
            "pii_data": None,
            "pii_detection_details": None,
            "secrets_detected": False,
            "secrets_data": None,
            "interesting_response": interesting_response,
            "regex_patterns_found": {},
            # Low-severity note: stack traces / debug pages; not a secret, not PII
            "debug_info": debug_info
        }

        if pii_detected:
            result["pii_data"] = {k: list(vv['values']) for k, vv in pii_data.items()}
            detection_details = {}
            for k, vv in pii_data.items():
                detection_details[k] = {
                    "detection_methods": list(vv['detection_methods'])
                }
            result["pii_detection_details"] = detection_details

        # Secrets are reported in their own fields, separate from PII
        if sensitive_info:
            result["secrets_detected"] = True
            result["secrets_data"] = {k: list(dict.fromkeys(v))[:2] for k, v in sensitive_info.items()}
            result["regex_patterns_found"] = {k: regex_patterns[k] for k in sensitive_info}
            if (status_code == 200 or (include_all and status_code == 404)):
                interesting_response = True
            result["interesting_response"] = interesting_response

        if verbose:
            if status_code == 200:
                log(f"{method.upper()} {full_url} returned {status_code}", level="SUCCESS")
            elif status_code == 404 and include_all:
                log(f"{method.upper()} {full_url} returned {status_code}", level="WARNING")
            elif 400 <= status_code < 600:
                log(f"{method.upper()} {full_url} returned {status_code}", level="WARNING")
            else:
                log(f"{method.upper()} {full_url} returned {status_code}", level="INFO")

        return result

    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error testing {method.upper()} {full_url}: {e}", level="DEBUG")
    return None

def test_endpoint(base_url, base_path, path_template, method, parameters, request_body=None,
                  content_type=None, verbose=False, include_all=False,
                  product_mode=False, brute=False):
    """
    Tests a single endpoint (method + path_template).
    Prepares final path by combining base_path with path_template, then calls test_parameter_values.
    Returns a list of results from that function.
    """
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    if base_path.endswith("/"):
        base_path = base_path[:-1]

    full_path = base_path + path_template
    parsed_base_url = urlparse(base_url)
    base_url_no_path = f"{parsed_base_url.scheme}://{parsed_base_url.netloc}"

    results = []
    try:
        start_time = time.time()
        endpoint_results = test_parameter_values(
            method, base_url_no_path, full_path, parameters,
            request_body, content_type, include_all, verbose, brute=brute
        )
        if endpoint_results:
            results.extend(endpoint_results)
    except Exception as e:
        if verbose:
            log(f"Error testing endpoint {method.upper()} {full_path}: {e}", level="DEBUG")
    finally:
        elapsed_time = time.time() - start_time
        if elapsed_time > TIMEOUT and verbose:
            log(f"Timeout reached while testing endpoint {method.upper()} {full_path}", level="WARNING")

    return results

def merge_parameters(path_params, op_params):
    """
    Combines path-level parameters (shared by every method on a path) with the
    operation's own. An operation parameter overrides a path one with the same name and location.
    """
    merged = {}
    for param in (path_params or []) + (op_params or []):
        if isinstance(param, dict):
            merged[(param.get('name'), param.get('in'))] = param
    return list(merged.values())

def test_endpoints(base_url, base_path, swagger_spec, verbose=False,
                   include_risk=False, include_all=False, product_mode=False,
                   tried_basepath_fallback=False, brute=False):
    """
    Iterates over all paths and methods in the provided swagger_spec.
    Submits tasks to test_endpoint if the method is allowed (GET or others if -risk).
    Returns all aggregated results. Also includes fallback if 80%+ are 404.
    """
    results = []
    if not swagger_spec or 'paths' not in swagger_spec:
        if verbose:
            log("Specification does not contain 'paths' key.", level="CRITICAL")
        return results

    # Inline $ref pointers once; the basepath fallback re-enters with the resolved spec
    if not tried_basepath_fallback:
        swagger_spec = resolve_refs(swagger_spec)

    unique_endpoints = set()
    all_results = []
    max_workers = min(100, os.cpu_count() * 5)

    # Learn what unknown routes look like, so catch-all 200s can be discarded
    methods_to_test = {'GET'} | ({'POST', 'PUT', 'PATCH', 'DELETE'} if include_risk else set())
    baselines = take_baselines(base_url, base_path, methods_to_test, verbose)
    filtered_count = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_endpoint = {}
        for path, methods in swagger_spec['paths'].items():
            if not methods:
                continue
            for mthd, details in methods.items():
                if mthd.lower() not in ['get','post','put','patch','delete']:
                    continue
                if mthd.upper() != 'GET' and not include_risk:
                    continue

                endpoint_key = (mthd.upper(), path)
                if endpoint_key in unique_endpoints:
                    continue
                unique_endpoints.add(endpoint_key)
                expected_types = declared_response_types(swagger_spec, details)
                auth_schemes = required_auth_schemes(swagger_spec, details)
                priv_reason = privileged_reason(path, swagger_spec, details)

                parameters = merge_parameters(methods.get('parameters', []), details.get('parameters', []))
                content_types = ['application/json']
                schema = None

                # If OpenAPI 3.x uses requestBody
                if 'requestBody' in details:
                    rb_content = details['requestBody'].get('content', {})
                    if not rb_content:
                        continue
                    content_types = list(rb_content.keys())
                    for ct in content_types:
                        media = rb_content[ct] or {}
                        schema = media.get('schema', {})
                        # A media-level example overrides the schema's own
                        media_example = param_example(media)
                        if media_example is not None:
                            schema = {**schema, 'example': media_example}
                        request_body = build_request_body(schema, ct)
                        fut = executor.submit(
                            test_endpoint,
                            base_url, base_path, path, mthd,
                            parameters, request_body, ct,
                            verbose, include_all,
                            product_mode=product_mode, brute=brute
                        )
                        future_to_endpoint[fut] = (mthd, path, ct, expected_types, auth_schemes, priv_reason)
                else:
                    # Swagger 2.0 with parameters
                    if parameters:
                        for param in parameters:
                            if param.get('in') == 'body' and 'schema' in param:
                                schema = param['schema']
                                break
                    request_body = build_request_body(schema, 'application/json')
                    fut = executor.submit(
                        test_endpoint,
                        base_url, base_path, path, mthd,
                        parameters, request_body, 'application/json',
                        verbose, include_all,
                        product_mode=product_mode, brute=brute
                    )
                    future_to_endpoint[fut] = (mthd, path, 'application/json', expected_types, auth_schemes, priv_reason)

        for future in as_completed(future_to_endpoint):
            mthd, pth, ct, expected_types, auth_schemes, priv_reason = future_to_endpoint[future]
            try:
                for res in future.result() or []:
                    reason = false_positive_reason(res, baselines, expected_types)
                    if reason:
                        filtered_count += 1
                        if verbose:
                            log(f"Discarding {res['method']} {res['url']}: {reason}", level="DEBUG")
                        continue
                    apply_auth_finding(res, auth_schemes)
                    res['privileged_reason'] = priv_reason
                    all_results.append(res)
            except Exception as exc:
                if verbose:
                    log(f"Endpoint {mthd.upper()} {pth} with content type {ct} generated an exception: {exc}", level="DEBUG")

    # Basepath fallback logic if 80%+ of responses are 404 with the same content length
    if not tried_basepath_fallback:
        num_responses = len(all_results)
        num_404s = sum(1 for r in all_results if r['status_code'] == 404)
        content_lengths = set(r['content_length'] for r in all_results if r['status_code'] == 404)
        if num_404s > 0 and num_responses > 0:
            proportion_404 = num_404s / num_responses
            if proportion_404 > 0.8 and len(content_lengths) == 1 and base_path != '/':
                if verbose:
                    log("Basepath fallback triggered. Retesting endpoints with basepath '/'.", level="INFO")
                all_results.clear()
                fallback = test_endpoints(
                    base_url, '/', swagger_spec, verbose,
                    include_risk, include_all, product_mode=product_mode,
                    tried_basepath_fallback=True, brute=brute
                )
                return fallback

    if filtered_count and not product_mode:
        log(f"Discarded {filtered_count} catch-all/soft-404 response(s) for {base_url}.", level="INFO")
    # _body_hash is kept here (used by the IDOR test) and stripped in main before output
    return all_results

def resolve_refs(spec):
    """
    Returns a copy of the spec with local $ref pointers (e.g. '#/components/schemas/User',
    '#/definitions/User', '#/components/parameters/id') replaced by their targets.
    Sibling keys next to a $ref are merged over the target. Circular references are
    cut off with an empty schema, and external or broken refs are left untouched.
    """
    cache = {}

    def lookup(ref):
        node = spec
        for part in ref[2:].split('/'):
            part = unquote(part).replace('~1', '/').replace('~0', '~')
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return None
        return node

    def resolve(node, stack):
        if isinstance(node, list):
            return [resolve(item, stack) for item in node]
        if not isinstance(node, dict):
            return node

        ref = node.get('$ref')
        if not (isinstance(ref, str) and ref.startswith('#/')):
            return {k: resolve(v, stack) for k, v in node.items()}
        if ref in stack:
            return {}
        if ref not in cache:
            target = lookup(ref)
            if target is None:
                return {k: resolve(v, stack) for k, v in node.items()}
            cache[ref] = resolve(target, stack | {ref})

        resolved = cache[ref]
        siblings = {k: resolve(v, stack) for k, v in node.items() if k != '$ref'}
        if siblings and isinstance(resolved, dict):
            return {**resolved, **siblings}
        return resolved

    return resolve(spec, frozenset())

def is_valid_spec(spec):
    """
    Returns True if a parsed document looks like a Swagger 2 / OpenAPI 3 spec.
    """
    return (
        isinstance(spec, dict)
        and ('swagger' in spec or 'openapi' in spec)
        and isinstance(spec.get('paths'), dict)
    )

def parse_spec_text(text):
    """
    Parses a response body as JSON, falling back to YAML. Returns None for HTML
    or anything that doesn't parse into a dict/list.
    """
    stripped = text.lstrip('﻿ \t\r\n')
    if not stripped or stripped.startswith('<'):
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        pass
    try:
        doc = yaml.safe_load(stripped)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, (dict, list)) else None

def spec_config_urls(doc):
    """
    Returns spec URLs listed by a Swagger UI config document rather than a spec:
    springdoc '/v3/api-docs/swagger-config' ({"url": ...} or {"urls": [{"url": ...}]})
    and Springfox '/swagger-resources' ([{"location": ...}, ...]).
    """
    entries = []
    if isinstance(doc, dict):
        if isinstance(doc.get('url'), str):
            entries.append(doc['url'])
        entries.extend(doc.get('urls') or [])
    elif isinstance(doc, list):
        entries = doc
    urls = []
    for entry in entries:
        if isinstance(entry, str):
            urls.append(entry)
        elif isinstance(entry, dict):
            target = entry.get('url') or entry.get('location')
            if isinstance(target, str):
                urls.append(target)
    return urls

def fetch_swagger_spec(url, verbose=False, _depth=0):
    """
    Attempts to fetch and parse an OpenAPI/Swagger spec from a given URL.
    The body is parsed as JSON or YAML whatever the Content-Type says, and accepted
    only if it is a real spec (has 'swagger'/'openapi' and a 'paths' object).
    Swagger UI config documents that point at specs are followed (one level deep).
    Returns the parsed spec as a dictionary or None if unsuccessful.
    """
    if verbose:
        log(f"Fetching Swagger/OpenAPI spec directly from {url}", level="DEBUG")
    try:
        resp = http_request('GET', url)
    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error fetching Swagger/OpenAPI spec from {url}: {e}", level="DEBUG")
        return None

    if resp.status_code != 200:
        if verbose:
            log(f"Invalid response from {url}: {resp.status_code}", level="DEBUG")
        return None

    doc = parse_spec_text(resp.text)
    if is_valid_spec(doc):
        if verbose:
            log(f"Successfully loaded spec from {url}", level="SUCCESS")
        return doc

    if _depth == 0:
        for config_url in spec_config_urls(doc):
            spec_url = urljoin(url, config_url)
            if verbose:
                log(f"Following spec URL from Swagger UI config: {spec_url}", level="DEBUG")
            spec = fetch_swagger_spec(spec_url, verbose, _depth=1)
            if spec:
                return spec

    if verbose:
        log(f"No valid spec at {url}", level="DEBUG")
    return None

def find_swagger_ui_docs(base_url, verbose=False):
    """
    Attempts to detect a Swagger UI at known paths by scanning for references
    to swagger/openapi in the HTML or embedded JavaScript. If found, attempts
    to parse the discovered spec path or extract an embedded spec.
    """
    for pth in SWAGGER_UI_PATHS:
        swagger_ui_url = urljoin(base_url, pth)
        if verbose:
            log(f"Checking Swagger UI page at {swagger_ui_url}", level="DEBUG")
        try:
            r = http_request('GET', swagger_ui_url, allow_redirects=False)
            if r.status_code == 200 and ('swagger' in r.text.lower() or 'openapi' in r.text.lower()):
                if verbose:
                    log(f"Swagger UI found at {swagger_ui_url}", level="DEBUG")
                spec_url = extract_spec_url_from_html(r.text)
                if spec_url:
                    full_spec_url = urljoin(swagger_ui_url, spec_url)
                    if verbose:
                        log(f"Found Swagger spec URL in HTML: {full_spec_url}", level="DEBUG")
                    # Spec URLs often have no extension (e.g. /v3/api-docs), so try anything that isn't JS
                    if not urlparse(full_spec_url).path.lower().endswith('.js'):
                        sp = fetch_swagger_spec(full_spec_url, verbose)
                        if sp:
                            return sp
                    else:
                        try:
                            js_r = http_request('GET', full_spec_url)
                            if js_r.status_code == 200:
                                if verbose:
                                    log(f"Attempting to extract embedded spec from JS file: {full_spec_url}", level="DEBUG")
                                emb = extract_spec_from_js(js_r.text)
                                if emb and isinstance(emb, dict):
                                    if verbose:
                                        log(f"Extracted embedded Swagger spec from JS file: {full_spec_url}", level="DEBUG")
                                    return emb
                        except requests.exceptions.RequestException as e:
                            if verbose:
                                log(f"Error fetching JS file {full_spec_url}: {e}", level="DEBUG")
                js_files = re.findall(r'<script\s+src=["\']([^"\']+\.js)["\']', r.text, re.IGNORECASE)
                if verbose:
                    log(f"Found {len(js_files)} JavaScript files to analyze.", level="DEBUG")
                js_files = [x for x in js_files if is_local_js_file(x, swagger_ui_url)]
                if verbose:
                    log(f"{len(js_files)} JavaScript files are local and will be analyzed.", level="DEBUG")
                js_files_sorted = sorted(js_files, key=lambda x: 'init' in x.lower(), reverse=True)
                for jsf in js_files_sorted:
                    jsu = urljoin(swagger_ui_url, jsf)
                    if verbose:
                        log(f"Fetching JS file: {jsu}", level="DEBUG")
                    try:
                        js_resp = http_request('GET', jsu)
                        if js_resp.status_code == 200:
                            spec_url_js = extract_spec_url_from_js(js_resp.text)
                            if spec_url_js:
                                full_spec_url_js = urljoin(jsu, spec_url_js)
                                if verbose:
                                    log(f"Found Swagger spec URL in JS: {full_spec_url_js}", level="DEBUG")
                                if not urlparse(full_spec_url_js).path.lower().endswith('.js'):
                                    sp2 = fetch_swagger_spec(full_spec_url_js, verbose)
                                    if sp2:
                                        return sp2
                                else:
                                    if full_spec_url_js.lower().endswith('.js'):
                                        try:
                                            nested_js = http_request('GET', full_spec_url_js)
                                            if nested_js.status_code == 200:
                                                emb2 = extract_spec_from_js(nested_js.text)
                                                if emb2 and isinstance(emb2, dict):
                                                    if verbose:
                                                        log(f"Extracted embedded Swagger spec from nested JS file: {full_spec_url_js}", level="DEBUG")
                                                    return emb2
                                        except requests.exceptions.RequestException as e:
                                            if verbose:
                                                log(f"Error fetching nested JS file {full_spec_url_js}: {e}", level="DEBUG")
                            emb = extract_spec_from_js(js_resp.text)
                            if emb and isinstance(emb, dict):
                                if verbose:
                                    log(f"Extracted embedded Swagger spec from JS file: {jsu}", level="DEBUG")
                                return emb
                    except requests.exceptions.RequestException as e:
                        if verbose:
                            log(f"Error fetching JS file {jsu}: {e}", level="DEBUG")
                spec_url_swash = extract_swashbuckle_config_spec_url(r.text)
                if spec_url_swash:
                    full_swash_url = urljoin(swagger_ui_url, spec_url_swash)
                    if verbose:
                        log(f"Found Swagger spec URL via swashbuckleConfig: {full_swash_url}", level="DEBUG")
                    sp3 = fetch_swagger_spec(full_swash_url, verbose)
                    if sp3:
                        return sp3
        except requests.exceptions.RequestException as e:
            if verbose:
                log(f"Error checking Swagger UI page at {swagger_ui_url}: {e}", level="DEBUG")
    return None

def extract_swashbuckle_config_spec_url(html_text):
    """
    Extracts a discovery path from window.swashbuckleConfig in the HTML if it exists.
    Returns the string path or None.
    """
    match = re.search(r'window\.swashbuckleConfig\s*=\s*{([\s\S]*?)};', html_text)
    if match:
        config_content = match.group(1)
        disc_paths = re.findall(r'discoveryPaths\s*:\s*\[\s*["\']([^"\']+)["\']\s*\]', config_content)
        if disc_paths:
            return disc_paths[0]
    return None

def is_local_js_file(js_file_url, base_url):
    """
    Determines if a JS file reference is local by comparing netloc to base_url's netloc.
    """
    parsed_js = urlparse(js_file_url)
    parsed_base = urlparse(base_url)
    if not parsed_js.netloc or parsed_js.netloc == parsed_base.netloc:
        return True
    return False

def extract_spec_url_from_html(html_text):
    """
    Extracts a potential swagger spec URL from HTML content
    by searching for 'url: "..."' patterns or SwaggerUIBundle references.
    """
    matches = re.findall(r'url:\s*["\'](.*?)["\']', html_text)
    if matches:
        return matches[0]
    matches = re.findall(r'SwaggerUIBundle\s*\(\s*{\s*url:\s*"(.*?)"', html_text, re.DOTALL)
    if matches:
        return matches[0]
    matches = re.findall(r'configUrl:\s*["\'](.*?)["\']', html_text)
    if matches:
        return matches[0]
    soup = BeautifulSoup(html_text, 'html.parser')
    for script in soup.find_all('script'):
        sc = script.string
        if sc and 'url:' in sc:
            mm = re.findall(r'url:\s*"(.*?)"', sc)
            if mm:
                return mm[0]
    return None

def extract_spec_url_from_js(js_text):
    """
    Extracts a swagger spec URL from JavaScript code by searching for
    various patterns like 'url: "..."', 'urls:[ { url:"..." } ]', etc.
    """
    patterns = [
        r'url:\s*["\'](.*?)["\']',
        r'urls:\s*\[\s*{\s*url:\s*["\'](.*?)["\']',
        r'configUrl:\s*["\'](.*?)["\']',
        r'defaultDefinitionUrl\s*=\s*["\'](.*?)["\']',
        r'definitionURL\s*=\s*["\'](.*?)["\']',
        # Last resort: a string constant that looks like a spec location
        r'const\s+\w+\s*=\s*["\']([^"\']*(?:swagger|openapi|api-docs)[^"\']*)["\']',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text)
        if matches:
            return matches[0]
    return None

def extract_spec_from_js(js_text):
    """
    Attempts to extract an embedded swagger spec from a JavaScript file.
    Removes comments, looks for object definitions with braces, and tries
    to parse them as JSON after minor adjustments.
    """
    js_text = re.sub(r'/\*[\s\S]*?\*/', '', js_text)
    # Skip '//' preceded by ':' so URLs like "https://..." inside the spec survive
    js_text = re.sub(r'(?<!:)//.*', '', js_text)

    patterns = [
        r'(?:var|let|const)\s+(\w+)\s*=\s*({[\s\S]*?});',
        r'(\w+)\s*=\s*({[\s\S]*?});',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text, re.DOTALL)
        for var_name, obj_str in matches:
            cleaned_str = js_object_to_json(obj_str)
            if cleaned_str:
                try:
                    spec = json.loads(cleaned_str)
                    # Any parseable object isn't enough; it must actually be a spec
                    if is_valid_spec(spec):
                        return spec
                except json.JSONDecodeError:
                    continue
    return None

def js_object_to_json(js_object_str):
    """
    Converts a JavaScript object string into a valid JSON string by
    replacing single quotes, adding quotes to keys, and removing trailing commas.
    """
    try:
        js_object_str = js_object_str.strip()
        js_object_str = re.sub(r"'", r'"', js_object_str)
        js_object_str = re.sub(r'([{,]\s*)(\w+)\s*:', r'\1"\2":', js_object_str)
        js_object_str = re.sub(r',\s*([}\]])', r'\1', js_object_str)
        return js_object_str
    except Exception:
        return None

def expand_server_url(server):
    """
    Substitutes OpenAPI 3 server variables (e.g. '{scheme}://{host}/v{version}')
    with their default (or first enum) values. Returns None if any stay unresolved.
    """
    url = server.get('url')
    if not isinstance(url, str):
        return None
    for name, var in (server.get('variables') or {}).items():
        if not isinstance(var, dict):
            continue
        value = var.get('default')
        if value is None and var.get('enum'):
            value = var['enum'][0]
        if value is not None:
            url = url.replace('{' + name + '}', str(value))
    if re.search(r'{[^}]*}', url):
        return None
    return url

def normalize_base_path(path):
    """
    Turns '', 'v1', './v1/' etc. into a clean absolute path like '/v1' (or '/').
    """
    path = (path or '').strip()
    while path.startswith('./'):
        path = path[2:]
    path = '/' + path.lstrip('/')
    return path.rstrip('/') or '/'

def determine_base_path(spec, base_url, verbose=False):
    """
    Works out the path prefix to put in front of every spec path.
    OpenAPI 3 'servers' URLs may be absolute (https://api.x.com/v1), templated
    ({scheme}://{host}/v1) or relative (/v1); only their path is used, since the
    scan always targets the host the user supplied. A server on that same host is
    preferred, then a relative one, then the first absolute one.
    Swagger 2 uses 'basePath'.
    """
    target_host = urlparse(base_url).netloc.lower()
    servers = spec.get('servers')

    if isinstance(servers, list) and servers:
        same_host, relative, other_host = [], [], []
        for server in servers:
            if not isinstance(server, dict):
                continue
            url = expand_server_url(server)
            if url is None:
                continue
            parsed = urlparse(url)
            if parsed.netloc:
                (same_host if parsed.netloc.lower() == target_host else other_host).append(parsed)
            else:
                relative.append(parsed)

        for group in (same_host, relative, other_host):
            if group:
                chosen = group[0]
                if group is other_host and verbose:
                    log(f"Spec declares server {chosen.scheme}://{chosen.netloc}; "
                        f"scanning {target_host} with path {chosen.path or '/'}", level="DEBUG")
                return normalize_base_path(chosen.path)
        return '/'

    if verbose and spec.get('host') and spec['host'].lower() != target_host:
        log(f"Spec declares host {spec['host']}; scanning {target_host} instead", level="DEBUG")
    return normalize_base_path(spec.get('basePath', '/'))

def process_input(urls):
    """
    Ensures each URL has a valid scheme (http or https).
    If not present, prepends https:// to the beginning.
    """
    processed = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        processed.append(url)
    return processed

def dig(data, dotted_path):
    """
    Follows a dotted path into nested dicts/lists, e.g. 'data.token' or
    'items.0.key'. Returns None if any step is missing.
    """
    node = data
    for part in dotted_path.split('.'):
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.lstrip('-').isdigit() and -len(node) <= int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node

def headers_from_sources(header_args=None, cookie=None, token=None, auth_file=None):
    """
    Builds a header dict from CLI/file inputs: repeated 'Name: value' headers,
    a Cookie string, a bearer token, and a JSON file of {"headers": {...},
    "cookie": "...", "token": "..."}. Later sources merge over earlier ones.
    """
    headers = {}
    if auth_file:
        with open(auth_file) as f:
            data = json.load(f)
        headers.update(data.get('headers') or {})
        if data.get('cookie'):
            headers['Cookie'] = data['cookie']
        if data.get('token'):
            headers['Authorization'] = f"Bearer {data['token']}"
    for raw in header_args or []:
        name, value = parse_header_arg(raw)
        headers[name] = value
    if cookie:
        headers['Cookie'] = cookie
    if token:
        headers['Authorization'] = f"Bearer {token}"
    return headers

def login_for_token(login_url, login_data, token_path="token",
                    token_header="Authorization", token_prefix="Bearer ", verbose=False):
    """
    Exchanges credentials for a token: POSTs login_data as JSON to login_url,
    reads the token at token_path from the JSON response, and returns it as a
    header dict. Returns None on failure.
    """
    try:
        resp = http_request('POST', login_url, identity=ANONYMOUS,
                            json=login_data, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        log(f"Login request to {login_url} failed: {e}", level="CRITICAL")
        return None
    if not 200 <= resp.status_code < 300:
        log(f"Login failed: {login_url} returned {resp.status_code}", level="CRITICAL")
        return None
    try:
        token = dig(resp.json(), token_path)
    except ValueError:
        token = None
    if not token:
        log(f"Login succeeded but no token at '{token_path}' in the response.", level="CRITICAL")
        return None
    if verbose:
        log(f"Obtained token from {login_url} (path '{token_path}').", level="SUCCESS")
    return {token_header: f"{token_prefix}{token}"}

def prompt_for_identity(name="user"):
    """
    Interactively collects credentials for one identity. Offers a raw
    token/header/cookie, or a username+password login against a login endpoint.
    Returns an Identity, or the anonymous one if the user supplies nothing.
    """
    console.print(f"\n[bold]Enter credentials for identity '{name}'[/bold] "
                  "(press Enter to skip a field).")
    console.print("  [1] Bearer token   [2] Raw header   [3] Cookie   "
                  "[4] Username/password login")
    choice = input("Method [1-4, default 1]: ").strip() or "1"

    try:
        if choice == "2":
            raw = input("Header (Name: value): ").strip()
            headers = dict([parse_header_arg(raw)]) if raw else {}
        elif choice == "3":
            cookie = input("Cookie string: ").strip()
            headers = {'Cookie': cookie} if cookie else {}
        elif choice == "4":
            login_url = input("Login URL: ").strip()
            user_field = input("Username field name [username]: ").strip() or "username"
            pass_field = input("Password field name [password]: ").strip() or "password"
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            token_path = input("Token path in response [token]: ").strip() or "token"
            headers = login_for_token(
                login_url, {user_field: username, pass_field: password},
                token_path=token_path, verbose=True
            ) or {}
        else:
            token = getpass.getpass("Bearer token: ").strip()
            headers = {'Authorization': f"Bearer {token}"} if token else {}
    except (ValueError, KeyboardInterrupt) as e:
        log(f"Credential entry cancelled: {e}", level="WARNING")
        headers = {}

    if not headers:
        log(f"No credentials entered for '{name}'; continuing anonymously.", level="WARNING")
        return ANONYMOUS
    return Identity(name, headers)

def build_identity(args):
    """
    Assembles the scan identity from CLI args: flags/file/login first, then an
    interactive prompt if --login was given (or the inputs were incomplete).
    Returns an Identity (anonymous if nothing was provided).
    """
    headers = headers_from_sources(args.header, args.cookie, args.token, args.auth_file)

    if args.login_url and not headers:
        if not args.login_data:
            log("--login-url needs --login-data (JSON credentials).", level="CRITICAL")
        else:
            try:
                creds = json.loads(args.login_data)
            except ValueError:
                log("--login-data must be valid JSON.", level="CRITICAL")
                creds = None
            if creds:
                headers = login_for_token(args.login_url, creds,
                                          token_path=args.token_path, verbose=args.verbose) or {}

    if args.login and not headers:
        if sys.stdin.isatty():
            return prompt_for_identity("user")
        log("--login needs an interactive terminal; use -H/--token/--auth-file instead.", level="CRITICAL")

    return Identity("user", headers) if headers else ANONYMOUS

def build_second_identity(args):
    """
    Assembles the second identity for the IDOR test from the *2 flags, or an
    interactive prompt (when --login is set and a terminal is available).
    Returns an Identity, or the anonymous one if nothing was provided.
    """
    headers = headers_from_sources(args.header2, args.cookie2, args.token2, args.auth_file2)
    if headers:
        return Identity("user2", headers)
    if args.login and sys.stdin.isatty():
        return prompt_for_identity("user2")
    return ANONYMOUS

def has_object_param(path_template):
    """
    True if a path has a placeholder that looks like an object identifier,
    e.g. /users/{id}, /orders/{orderId}, /files/{uuid} — the endpoints where
    broken object-level authorization (IDOR) lives.
    """
    names = re.findall(r'\{([^}]+)\}|:([A-Za-z_]\w*)|<([^>]+)>', path_template)
    flat = [n for group in names for n in group if n]
    return any(re.search(r'(^|_)(id|uuid|guid|key|ref|no|num|slug)$', n.lower()) or n.lower() in
               ('id', 'uuid', 'guid', 'key') for n in flat)

def fetch_as(method, url, identity, verbose=False):
    """
    Re-requests a URL as a given identity and summarizes the response for IDOR
    comparison: status, body fingerprint, length and content type. None on error.
    """
    try:
        resp = http_request(method, url, identity=identity, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"IDOR re-request {method} {url} as '{identity.name}' failed: {e}", level="DEBUG")
        return None
    return {
        'status_code': resp.status_code,
        'body_hash': body_fingerprint(resp.content, urlparse(url).path),
        'content_length': len(resp.content),
        'content_type': short_content_type(resp),
    }

def test_idor(primary_results, identity_b, verbose=False):
    """
    Broken object-level authorization check. For each object endpoint that the
    primary identity (A) read successfully, re-requests the SAME url as identity B
    and as anonymous. If either gets a 2xx whose body matches A's, that party can
    read A's object -> IDOR/BOLA. Only GET is replayed (re-reading is non-destructive).
    Returns a list of finding dicts.
    """
    seen = set()
    candidates = []
    for r in primary_results:
        if r['method'] != 'GET':
            continue
        if not (200 <= r['status_code'] < 300):
            continue
        if not has_object_param(r['path_template']):
            continue
        if not r.get('_body_hash'):
            continue
        if r['url'] in seen:
            continue
        seen.add(r['url'])
        candidates.append(r)

    if not candidates:
        log("IDOR: no object-level GET endpoints were accessible as the primary identity; nothing to compare.",
            level="INFO")
        return []

    log(f"IDOR: replaying {len(candidates)} object endpoint(s) as '{identity_b.name}' and anonymous.",
        level="INFO")

    testers = [identity_b]
    if identity_b is not ANONYMOUS:
        testers.append(ANONYMOUS)

    findings = []
    for r in candidates:
        for tester in testers:
            other = fetch_as(r['method'], r['url'], tester, verbose)
            if not other:
                continue
            authed = 200 <= other['status_code'] < 300
            same_object = authed and other['body_hash'] == r['_body_hash']
            if not same_object:
                continue
            # Anonymous access to A's object is worse than cross-user access
            severity = 'critical' if tester is ANONYMOUS else 'high'
            findings.append({
                'test': 'idor',
                'method': r['method'],
                'url': r['url'],
                'path_template': r['path_template'],
                'owner_identity': r['identity'],
                'tested_as': tester.name,
                'status_code': other['status_code'],
                'content_length': other['content_length'],
                'severity': severity,
                'findings': [f"BOLA/IDOR: '{tester.name}' received the same object that "
                             f"'{r['identity']}' accessed at {urlparse(r['url']).path}"],
            })
            if verbose:
                log(f"IDOR: {tester.name} read {r['url']} (owned via {r['identity']})", level="WARNING")
    return findings

def test_privesc(primary_results, low_priv_identity, verbose=False):
    """
    Privilege-escalation check. For each privileged endpoint the primary identity
    (expected to be an admin) could read, re-requests the SAME url as the
    lower-privilege identity and anonymously. A 2xx for them means the endpoint
    did not enforce the privilege. GET only (re-reading is non-destructive).
    Returns a list of finding dicts.
    """
    seen = set()
    candidates = []
    for r in primary_results:
        if r['method'] != 'GET' or not (200 <= r['status_code'] < 300):
            continue
        if not r.get('privileged_reason') or not r.get('_body_hash'):
            continue
        if r['url'] in seen:
            continue
        seen.add(r['url'])
        candidates.append(r)

    if not candidates:
        log("Privilege escalation: no privileged GET endpoints were accessible as the primary "
            "(admin) identity; nothing to compare.", level="INFO")
        return []

    log(f"Privilege escalation: replaying {len(candidates)} privileged endpoint(s) as "
        f"'{low_priv_identity.name}' and anonymous.", level="INFO")

    testers = [low_priv_identity]
    if low_priv_identity is not ANONYMOUS:
        testers.append(ANONYMOUS)

    findings = []
    for r in candidates:
        for tester in testers:
            other = fetch_as(r['method'], r['url'], tester, verbose)
            if not other or not (200 <= other['status_code'] < 300):
                continue
            same = other['body_hash'] == r['_body_hash']
            anon = tester is ANONYMOUS
            if same:
                severity = 'critical' if anon else 'high'
                detail = (f"Privilege escalation: '{tester.name}' received the same privileged "
                          f"response as '{r['identity']}'")
            else:
                # Not rejected, but different body: worth manual review, lower confidence
                severity = 'high' if anon else 'medium'
                detail = (f"Privilege escalation: privileged endpoint returned "
                          f"HTTP {other['status_code']} to '{tester.name}' (expected 401/403)")
            findings.append({
                'test': 'privesc',
                'method': r['method'],
                'url': r['url'],
                'path_template': r['path_template'],
                'privileged_reason': r['privileged_reason'],
                'owner_identity': r['identity'],
                'tested_as': tester.name,
                'status_code': other['status_code'],
                'content_length': other['content_length'],
                'severity': severity,
                'findings': [detail],
            })
            if verbose:
                log(f"Privesc: {tester.name} reached {r['url']} ({r['privileged_reason']})", level="WARNING")
    return findings

def print_privesc_findings(privesc_findings):
    """
    Prints the privilege-escalation findings as their own table.
    """
    table = Table(title="Privilege Escalation Findings", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("URL", style="magenta", overflow="fold")
    table.add_column("Reached by", style="red", no_wrap=True)
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("Privileged because", overflow="fold")
    for f in privesc_findings:
        sev_style = SEVERITY_STYLES[f['severity']]
        table.add_row(
            f"[{sev_style}]{f['severity'].upper()}[/{sev_style}]",
            f['method'], f['url'], f['tested_as'], str(f['status_code']),
            escape(f['privileged_reason'] or ""),
        )
    output_console.print(table)

def print_idor_findings(idor_findings):
    """
    Prints the IDOR/BOLA findings as their own table.
    """
    table = Table(title="IDOR / BOLA Findings", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("URL", style="magenta", overflow="fold")
    table.add_column("Accessed by", style="red", no_wrap=True)
    table.add_column("Status", style="green", no_wrap=True)
    for f in idor_findings:
        sev_style = SEVERITY_STYLES[f['severity']]
        table.add_row(
            f"[{sev_style}]{f['severity'].upper()}[/{sev_style}]",
            f['method'], f['url'], f['tested_as'], str(f['status_code']),
        )
    output_console.print(table)

def main(urls, verbose, include_risk, include_all, product_mode, stats_flag, rate, brute, json_output,
         output_file=None, identity=None, identity_b=None, idor=False, privesc=False):
    """
    Main function controlling flow:
    1. Tracks start time
    2. Processes input URLs
    3. Creates concurrency for scanning each host
    4. Accumulates results
    5. Prints or outputs final results and stats
    """
    global SCAN_START_TIME, SCAN_END_TIME, TOTAL_REQUESTS, AUTH_REQUIRED_COUNT
    SCAN_START_TIME = time.time()  # Start the timer
    rate_limiter.set_rate(rate)
    AUTH_REQUIRED_COUNT = 0
    if identity is not None:
        set_active_identity(identity)
    scan_identity = active_identity

    all_results = []
    processed_urls = process_input(urls)
    results_lock = threading.Lock()

    stats = {
        "scan_identity": active_identity.name,
        "unique_hosts_provided": len(set(urlparse(u).netloc for u in processed_urls)),
        "active_hosts": 0,
        "hosts_with_valid_spec": 0,
        "hosts_with_valid_endpoint": 0,
        "hosts_with_pii": 0,
        "hosts_with_secrets": 0,
        "pii_detection_methods": set(),
        "percentage_hosts_with_endpoint": 0,
        "regexes_found": set()
    }

    def record_host_results(rslts):
        """
        Adds one host's results to the overall list and updates the per-host stats.
        Each host is counted once, however many of its endpoints have findings.
        """
        with results_lock:
            all_results.extend(rslts)
            if not rslts:
                return
            stats["hosts_with_valid_endpoint"] += 1
            pii_results = [rr for rr in rslts if rr['pii_detected']]
            secret_results = [rr for rr in rslts if rr['secrets_detected']]
            if pii_results:
                stats["hosts_with_pii"] += 1
            if secret_results:
                stats["hosts_with_secrets"] += 1
            for rr in pii_results:
                for details in (rr['pii_detection_details'] or {}).values():
                    stats["pii_detection_methods"].update(details['detection_methods'])
            for rr in secret_results:
                stats["regexes_found"].update(rr['regex_patterns_found'])

    def process_url(base_url):
        """
        Scans a single base_url to find a swagger spec using direct spec,
        swagger-ui detection, or known direct paths. If found, calls test_endpoints.
        Accumulates results and updates stats accordingly.
        """
        nonlocal all_results, stats
        parsed_input_url = urlparse(base_url)
        host = parsed_input_url.netloc

        with lock:
            stats["active_hosts"] += 1

        # Check if the URL might be a direct spec: it ends with .json/.yaml/.yml, or it
        # has a path (e.g. /v3/api-docs) that serves a spec without an extension
        has_spec_ext = any(base_url.lower().endswith(ext) for ext in ['.json', '.yaml', '.yml'])
        direct_spec = None
        if not has_spec_ext and parsed_input_url.path.strip('/'):
            direct_spec = fetch_swagger_spec(base_url, verbose)
        if has_spec_ext or direct_spec:
            if not product_mode:
                log(f"Processing direct spec URL: {base_url}", level="INFO")
            swagger_spec = direct_spec or fetch_swagger_spec(base_url, verbose)
            if swagger_spec:
                with lock:
                    stats["hosts_with_valid_spec"] += 1
                if not product_mode:
                    log("Successfully loaded spec.", level="INFO")
                base_path = determine_base_path(swagger_spec, base_url, verbose)
                if not product_mode:
                    log("Scanning endpoints.", level="INFO")
                rslts = test_endpoints(
                    base_url, base_path, swagger_spec,
                    verbose, include_risk, include_all,
                    product_mode=product_mode, brute=brute
                )
                del swagger_spec
                record_host_results(rslts)
                return
            else:
                if verbose:
                    log(f"Failed to parse spec from {base_url}", level="DEBUG")
                with lock:
                    bad_hosts.add(host)
                return

        # Phase 1 & 2: Look for swagger UI
        swagger_spec = find_swagger_ui_docs(base_url, verbose)
        if swagger_spec:
            with lock:
                stats["hosts_with_valid_spec"] += 1
            if not product_mode:
                log(f"Spec identified via Swagger-UI detection.", level="INFO")
            base_path = determine_base_path(swagger_spec, base_url, verbose)
            if not product_mode:
                log("Scanning endpoints.", level="INFO")
            rslts = test_endpoints(
                base_url, base_path, swagger_spec,
                verbose, include_risk, include_all,
                product_mode=product_mode, brute=brute
            )
            del swagger_spec
            record_host_results(rslts)
            return

        # Phase 3: Direct spec path detection
        if verbose:
            log(f"Proceeding to Phase 3: Direct Spec Path Detection for {base_url}", level="DEBUG")
        for pth in DIRECT_SPEC_PATHS:
            spec_url = urljoin(base_url, pth)
            if verbose:
                log(f"Attempting to fetch spec from direct path: {spec_url}", level="DEBUG")
            sws = fetch_swagger_spec(spec_url, verbose)
            if sws:
                with lock:
                    stats["hosts_with_valid_spec"] += 1
                if not product_mode:
                    log(f"Spec identified via direct path detection: {spec_url}", level="INFO")
                base_path = determine_base_path(sws, base_url, verbose)
                if not product_mode:
                    log("Scanning endpoints.", level="INFO")
                rslts2 = test_endpoints(
                    base_url, base_path, sws,
                    verbose, include_risk, include_all,
                    product_mode=product_mode, brute=brute
                )
                del sws
                record_host_results(rslts2)
                return
        else:
            if verbose:
                log(f"No valid Swagger/OpenAPI spec found for {base_url}.", level="DEBUG")
                log(f"Failed to parse spec from {base_url}", level="DEBUG")
            else:
                log(f"No spec found for {base_url}.", level="INFO")
            with lock:
                bad_hosts.add(host)

    if not product_mode:
        print_banner()
    if scan_identity.authenticated:
        log(f"Scanning as authenticated identity '{scan_identity.name}'.", level="INFO")

    max_workers2 = min(100, os.cpu_count() * 5, len(processed_urls)) if len(processed_urls) > 0 else 1
    with ThreadPoolExecutor(max_workers=max_workers2) as executor:
        futs = {executor.submit(process_url, url): url for url in processed_urls}
        if not product_mode:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Processing URLs", total=len(futs))
                for fut in as_completed(futs):
                    u = futs[fut]
                    try:
                        fut.result()
                    except Exception as exc:
                        if verbose:
                            log(f"Error processing URL {u}: {exc}", level="DEBUG")
                    progress.update(task, advance=1)
        else:
            for fut in as_completed(futs):
                u = futs[fut]
                try:
                    fut.result()
                except Exception as exc:
                    if verbose:
                        log(f"Error processing URL {u}: {exc}", level="DEBUG")

    # IDOR / BOLA: replay the primary identity's object reads as the second identity
    idor_findings = []
    if idor:
        if identity_b is None or not identity_b.authenticated:
            log("IDOR test skipped: a second identity is required "
                "(--token2/--auth-file2/--header2, or interactive --login with --idor).", level="WARNING")
        elif not scan_identity.authenticated:
            log("IDOR test skipped: scan as a primary identity too (-H/--token/--login).", level="WARNING")
        else:
            idor_findings = test_idor(all_results, identity_b, verbose)

    # Privilege escalation: replay the admin identity's privileged reads as the lower-privilege one
    privesc_findings = []
    if privesc:
        if not scan_identity.authenticated:
            log("Privilege escalation test skipped: scan as the admin identity "
                "(-H/--token/--login).", level="WARNING")
        else:
            # Second identity is the lower-privilege user; fall back to anonymous if absent
            low_priv = identity_b if (identity_b and identity_b.authenticated) else ANONYMOUS
            if low_priv is ANONYMOUS:
                log("Privilege escalation: no second identity given; testing anonymous access only.",
                    level="INFO")
            privesc_findings = test_privesc(all_results, low_priv, verbose)

    # Internal field kept only for the IDOR/privesc comparison; strip before output
    for res in all_results:
        res.pop('_body_hash', None)

    SCAN_END_TIME = time.time()  # End the timer
    scan_duration = SCAN_END_TIME - SCAN_START_TIME

    if stats["active_hosts"] > 0:
        stats["percentage_hosts_with_endpoint"] = round(
            (stats["hosts_with_valid_endpoint"] / stats["active_hosts"]) * 100, 2
        )
    else:
        stats["percentage_hosts_with_endpoint"] = 0.0

    stats["pii_detection_methods"] = sorted(stats["pii_detection_methods"])
    stats["regexes_found"] = sorted(stats["regexes_found"])

    # Add total requests + average requests per second
    stats["total_requests_sent"] = TOTAL_REQUESTS
    if scan_duration > 0:
        stats["average_requests_per_second"] = round(TOTAL_REQUESTS / scan_duration, 2)
    else:
        stats["average_requests_per_second"] = 0.0

    if product_mode:
        grouped_results = {}
        for r in all_results:
            if r['pii_detected'] or r['secrets_detected'] or r['interesting_response']:
                key = (r['method'], r['path_template'])
                existing = grouped_results.get(key)
                if not existing or response_rank(r) > response_rank(existing):
                    grouped_results[key] = r

        final_results = sort_results(grouped_results.values())

        clean_final_results = []
        for r in final_results:
            clean_res = {kk: vv for kk, vv in r.items() if kk != 'path_template'}
            if not clean_res['body']:
                del clean_res['body']
            if 'pii_data' in clean_res and clean_res['pii_data']:
                clean_res['pii_data'] = clean_res['pii_data']
                clean_res['pii_detection_details'] = r['pii_detection_details']
            clean_final_results.append(clean_res)

        output = {"results": clean_final_results}
        if idor_findings:
            output["idor_findings"] = idor_findings
        if privesc_findings:
            output["privesc_findings"] = privesc_findings
        if stats_flag:
            output["stats"] = stats
        output_console.print_json(data=output)
        report_results = clean_final_results
    else:
        grouped_results = {}
        for r in all_results:
            key = (r['method'], r['path_template'])
            existing = grouped_results.get(key)
            if not existing or response_rank(r) > response_rank(existing):
                grouped_results[key] = r

        final_results = sort_results(grouped_results.values())

        if include_all:
            final_results = [
                rr for rr in final_results
                if rr['status_code'] not in [401, 403]
            ]
        else:
            # 2xx responses, plus any response that leaked a secret (e.g. in a 500 error page)
            final_results = [
                rr for rr in final_results
                if 200 <= rr['status_code'] < 300 or rr['severity'] == 'critical'
            ]

        report_results = final_results
        if json_output:
            out = {"results": final_results}
            if idor_findings:
                out["idor_findings"] = idor_findings
            if privesc_findings:
                out["privesc_findings"] = privesc_findings
            if stats_flag:
                out["stats"] = stats
            output_console.print_json(data=out)
        elif final_results:
            # One table per host, so multi-target scans stay readable
            by_host = {}
            for rr in final_results:
                parsed = urlparse(rr['url'])
                by_host.setdefault(f"{parsed.scheme}://{parsed.netloc}", []).append(rr)

            for host, host_results in by_host.items():
                table = Table(title=f"API Endpoints: {host}", show_lines=True)
                table.add_column("Severity", no_wrap=True)
                table.add_column("Method", style="cyan", no_wrap=True)
                table.add_column("Path", style="magenta", overflow="fold")
                table.add_column("Status", style="green", no_wrap=True)
                table.add_column("Size", style="yellow", justify="right", no_wrap=True)
                table.add_column("Findings", overflow="fold")
                if include_risk:
                    table.add_column("Body", style="blue", overflow="fold")

                for rr in host_results:
                    parsed = urlparse(rr['url'])
                    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                    sev_style = SEVERITY_STYLES[rr['severity']]
                    row = [
                        f"[{sev_style}]{rr['severity'].upper()}[/{sev_style}]",
                        rr['method'],
                        escape(path),
                        str(rr['status_code']),
                        f"{rr['content_length']:,}",
                        escape("\n".join(rr['findings'])) if rr['findings'] else "[dim]-[/dim]"
                    ]
                    if include_risk:
                        body_content = rr['body'] if rr['body'] else ""
                        row.append(escape(str(body_content)))
                    table.add_row(*row)

                output_console.print(table)
        else:
            log("No valid API responses found.", level="INFO")

        if idor_findings and not json_output:
            print_idor_findings(idor_findings)

        if privesc_findings and not json_output:
            print_privesc_findings(privesc_findings)

        if stats_flag and not json_output:
            stats_table = Table(title="Scan Statistics", show_lines=False)
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="magenta")

            formatted_stats = stats.copy()
            formatted_stats["percentage_hosts_with_endpoint"] = f"{formatted_stats['percentage_hosts_with_endpoint']}%"
            formatted_stats["pii_detection_methods"] = ', '.join(formatted_stats["pii_detection_methods"])
            formatted_stats["regexes_found"] = ', '.join(formatted_stats["regexes_found"])

            for k, v in formatted_stats.items():
                if isinstance(v, float):
                    v = f"{v:.2f}"
                elif isinstance(v, int):
                    v = f"{v:,}"
                stats_table.add_row(k.replace('_',' ').title(), str(v))

            output_console.print(stats_table)

    stats["auth_required_endpoints"] = AUTH_REQUIRED_COUNT
    stats["idor_findings"] = len(idor_findings)
    stats["privesc_findings"] = len(privesc_findings)
    # Nudge toward authenticated testing when anonymous and endpoints needed auth
    if not scan_identity.authenticated and AUTH_REQUIRED_COUNT > 0 and not product_mode:
        log(f"{AUTH_REQUIRED_COUNT} endpoint(s) returned 401/403 (authentication required). "
            "Rerun with --login (or -H/--token) to test them as a logged-in user.",
            level="INFO")

    # Save the full report (results + stats) as JSON if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump({"results": report_results, "idor_findings": idor_findings,
                       "privesc_findings": privesc_findings, "stats": stats}, f, indent=2, default=str)
        log(f"Results written to {output_file}", level="INFO")

    # Writes any bad hosts to a file for reference
    if bad_hosts:
        bad_hosts_file = os.path.expanduser("~/.autoswagger/logs/bad-hosts.txt")
        os.makedirs(os.path.dirname(bad_hosts_file), exist_ok=True)
        with open(bad_hosts_file, 'a') as f:
            for host in bad_hosts:
                f.write(host + '\n')

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Autoswagger: Detect unauthenticated access control issues via Swagger/OpenAPI documentation.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example usage:\n  python autoswagger.py https://api.example.com -v "
    )
    parser.add_argument("urls", nargs="*", help="Base URL(s) or spec URL(s) of the target API(s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-risk", action="store_true", help="Include non-GET requests in testing")
    parser.add_argument("-all", action="store_true", help="Include all HTTP status codes in the results, excluding 401 and 403")
    parser.add_argument("-product", action="store_true", help="Output all endpoints in JSON, flagging those that contain PII or have large responses.")
    parser.add_argument("-stats", action="store_true", help="Display scan statistics. Included in JSON if -product or -json is used.")
    parser.add_argument("-rate", type=int, default=30, help="Set the rate limit in requests per second (default: 30). Use 0 to disable rate limiting.")
    parser.add_argument("-b", "--brute", action="store_true", help="Enable exhaustive testing of parameter values.")
    parser.add_argument("-json", action="store_true", help="Output results in JSON format in default mode.")
    parser.add_argument("-o", "--output", metavar="FILE", help="Also write results and stats as JSON to FILE.")

    auth = parser.add_argument_group("authenticated testing")
    auth.add_argument("-H", "--header", action="append", metavar="'Name: value'",
                      help="Header sent with every request (repeatable), e.g. -H 'Authorization: Bearer ...'.")
    auth.add_argument("--cookie", metavar="STRING", help="Cookie header sent with every request.")
    auth.add_argument("--token", metavar="TOKEN", help="Shortcut for -H 'Authorization: Bearer TOKEN'.")
    auth.add_argument("--auth-file", metavar="FILE",
                      help="JSON file with {\"headers\": {...}, \"cookie\": \"...\", \"token\": \"...\"}.")
    auth.add_argument("--login", action="store_true",
                      help="Prompt interactively for credentials before scanning.")
    auth.add_argument("--login-url", metavar="URL",
                      help="Log in by POSTing --login-data (JSON) here and reading a token from the response.")
    auth.add_argument("--login-data", metavar="JSON",
                      help="JSON credentials for --login-url, e.g. '{\"username\":\"a\",\"password\":\"b\"}'.")
    auth.add_argument("--token-path", metavar="PATH", default="token",
                      help="Dotted path to the token in the login response (default: token).")

    idor = parser.add_argument_group("authorization testing (IDOR / BOLA)")
    idor.add_argument("--idor", action="store_true",
                      help="After scanning as the primary identity, replay object reads as a second "
                           "identity and anonymously, flagging cross-user access. Needs two identities.")
    idor.add_argument("--header2", action="append", metavar="'Name: value'",
                      help="Header for the second identity (repeatable).")
    idor.add_argument("--cookie2", metavar="STRING", help="Cookie for the second identity.")
    idor.add_argument("--token2", metavar="TOKEN", help="Bearer token for the second identity.")
    idor.add_argument("--auth-file2", metavar="FILE", help="Auth JSON file for the second identity.")
    idor.add_argument("--privesc", action="store_true",
                      help="Scan as the primary (admin) identity, then check whether the second "
                           "identity or anonymous requests can reach privileged (admin) endpoints.")

    args = parser.parse_args()

    if not args.urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        urls = args.urls

    if not urls:
        print_banner()
        parser.print_help()
        sys.exit()

    product_mode = args.product
    verbose = args.verbose
    include_risk = args.risk
    include_all = args.all
    stats_flag = args.stats
    rate = args.rate
    brute = args.brute
    json_output = args.json

    # Set up file logging if verbose is enabled
    if verbose:
        log_dir = os.path.expanduser("~/.autoswagger/logs")
        os.makedirs(log_dir, exist_ok=True)
        log_filename = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-log.txt")
        log_file_path = os.path.join(log_dir, log_filename)
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.propagate = False

    scan_identity = build_identity(args)
    second_identity = build_second_identity(args) if (args.idor or args.privesc) else None

    main(urls, verbose, include_risk, include_all, product_mode, stats_flag, rate, brute, json_output,
         args.output, identity=scan_identity, identity_b=second_identity, idor=args.idor, privesc=args.privesc)
