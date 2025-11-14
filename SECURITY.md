# Security Policy

## Security Posture

AFL Overseer is designed as a **read-only monitoring and visualization tool** with security as a primary consideration. The application is safe to expose to the internet with the following guarantees:

### Static, Read-Only Design

- **No User Input**: The web interface accepts ZERO user input
- **No Forms**: No HTML forms, text inputs, or file uploads
- **GET Requests Only**: All HTTP endpoints are read-only GET requests
- **No Write Operations**: Web interface performs no file writes or modifications
- **No Authentication Bypass**: No authentication system means no authentication to bypass

### Attack Surface Analysis

#### Web Server (`src/webserver.py`)
- ✅ **Only 2 endpoints**:
  - `GET /` - Serves static HTML dashboard
  - `GET /api/stats` - Returns JSON statistics
- ✅ **No query parameters** accepted or processed
- ✅ **No POST/PUT/DELETE** methods
- ✅ **No file operations** based on user input
- ✅ **No path traversal** vulnerabilities (no user-controlled paths)
- ✅ **No command injection** (no shell commands from user data)
- ✅ **No SQL injection** (no database)
- ✅ **No XSS** (no user input rendered)
- ✅ **No CSRF** (no state-changing operations)
- ✅ **Thread-safe** with proper locking mechanisms

#### TUI (`src/tui.py`)
- ✅ **Local only** - Not exposed to network
- ✅ **Read-only** - Only displays data
- ✅ **No remote code execution** vectors

#### File System Access
- ✅ **Read-only access** to AFL fuzzer directories
- ✅ **No writes** to AFL directories
- ✅ **State file** (`~/.afl-monitor-ng.json`) - Local only, not web-accessible
- ✅ **File locking** implemented with fcntl to prevent race conditions
- ✅ **Atomic writes** using temp file + rename pattern

### Security Best Practices Implemented

1. **Dependency Security**: All dependencies are well-maintained, popular libraries:
   - `aiohttp` - Mature async web framework
   - `textual` - Modern TUI framework
   - `rich` - Terminal formatting
   - `click` - CLI framework
   - `psutil` - System monitoring

2. **Thread Safety**:
   - Class-level locks for shared state
   - File-based locking with fcntl
   - Async locks for concurrent request handling
   - Atomic file operations

3. **Error Handling**:
   - All exceptions caught and logged
   - No sensitive information in error messages
   - Graceful degradation on failures

4. **Code Quality**:
   - Type hints throughout
   - Automated linting with pylint, flake8, black
   - Security scanning with bandit
   - Vulnerability scanning with safety and Trivy

### Recommended Deployment

While AFL Overseer is designed to be secure, we recommend:

1. **Firewall**: Limit web interface access to trusted networks/IPs
2. **Reverse Proxy**: Use nginx/apache with:
   - Rate limiting
   - SSL/TLS termination
   - Additional access controls
3. **Monitoring**: Monitor web server logs for unusual patterns
4. **Updates**: Keep dependencies updated

### Known Limitations

1. **No Authentication**: Web interface has no authentication system
   - **Mitigation**: Use network-level access controls

2. **Information Disclosure**: Fuzzing statistics are publicly readable
   - **Mitigation**: Don't expose sensitive target information in fuzzer names

3. **DoS Potential**: Rapid requests could consume resources
   - **Mitigation**: Use reverse proxy rate limiting

### Reporting Security Issues

If you discover a security vulnerability, please report it to:
- GitHub Issues: https://github.com/kirit1193/afl-overseer/issues
- Email: (create a security contact if needed)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Audit Results

**Last Audit**: 2024
- Static Analysis: ✅ PASS (pylint, flake8, bandit)
- Dependency Check: ✅ PASS (safety, Trivy)
- Manual Code Review: ✅ PASS
- Attack Surface Analysis: ✅ MINIMAL

**Verdict**: Safe for internet exposure with network-level access controls.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Updates

Security updates will be released as patch versions. Subscribe to repository releases for notifications.
