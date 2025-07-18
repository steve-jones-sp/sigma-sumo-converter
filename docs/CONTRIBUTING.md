# Contributing to Sigma to Sumo Logic CSE Converter

Thank you for considering contributing to the Sigma to Sumo Logic CSE Converter! This document provides guidelines and information for contributors.

## 🎯 How to Contribute

### Types of Contributions

We welcome several types of contributions:

1. **🗺️ Field Mappings**: Add support for new log sources
2. **🐛 Bug Fixes**: Fix issues and improve reliability  
3. **✨ Features**: Enhance converter functionality
4. **📚 Documentation**: Improve guides and examples
5. **🧪 Testing**: Add test cases and improve coverage
6. **🔧 Tooling**: Improve development workflow

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/sigma-sumo-converter.git
   cd sigma-sumo-converter
   ```
3. **Set up development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements-dev.txt
   ```
4. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

## 🗺️ Adding Field Mappings

### Process for New Log Sources

1. **Research the log source**:
   - Understand the log format and fields
   - Identify which Sumo Logic CSE normalized fields map to each source field
   - Review existing similar mappings for consistency

2. **Create the mapping file**:
   ```bash
   # Choose appropriate directory based on Sigma taxonomy
   touch field_mappings/product/new_product.json
   # or
   touch field_mappings/category/new_category.json
   ```

3. **Define the mapping structure**:
   ```json
   {
     "description": "Clear description of the log source",
     "logsource_conditions": [
       "metadata_vendor=\"VendorName\"",
       "metadata_product=\"ProductName\"",
       "metadata_productLogName=\"LogType\""
     ],
     "field_mappings": {
       "sourceField": "sumoLogicField",
       "anotherField": "fields[\"customField\"]"
     }
   }
   ```

4. **Test the mapping**:
   ```bash
   # Create test Sigma rule
   touch tests/fixtures/sample_rules/new_product_test.yml
   
   # Add expected output
   touch tests/fixtures/expected_outputs/new_product_test.json
   
   # Run tests
   python -m pytest tests/test_new_product.py -v
   ```

### Field Mapping Guidelines

#### Sumo Logic CSE Normalized Schema Fields

**Core Entity Fields:**
- `device_hostname` - Host/device name
- `user_username` - Username
- `user_userId` - User ID
- `user_authDomain` - Authentication domain

**Network Fields:**
- `srcDevice_ip` - Source IP address
- `dstDevice_ip` - Destination IP address
- `srcPort` - Source port
- `dstPort` - Destination port
- `srcDevice_mac` - Source MAC address
- `dstDevice_mac` - Destination MAC address

**Process Fields:**
- `baseImage` - Process executable path
- `commandLine` - Process command line
- `pid` - Process ID
- `parentBaseImage` - Parent process executable
- `parentCommandLine` - Parent process command line
- `parentPid` - Parent process ID

**File Fields:**
- `file_basename` - File name
- `file_path` - File path
- `file_hash_md5` - MD5 hash
- `file_hash_sha1` - SHA1 hash
- `file_hash_sha256` - SHA256 hash
- `file_hash_imphash` - Import hash
- `file_mimeType` - MIME type
- `file_size` - File size

**HTTP Fields:**
- `http_url` - Full URL
- `http_url_path` - URL path
- `http_url_queryString` - Query string
- `http_hostname` - Host header
- `http_method` - HTTP method
- `http_response_statusCode` - Response code
- `http_userAgent` - User agent
- `http_referer` - Referer header

**Event Fields:**
- `action` - Action performed
- `timestamp` - Event timestamp
- `metadata_vendor` - Log source vendor
- `metadata_product` - Log source product
- `metadata_deviceEventId` - Event ID
- `metadata_productLogName` - Log name

**Custom Fields:**
- `fields["customField"]` - For vendor-specific fields

#### Mapping Best Practices

1. **Use normalized fields when possible**:
   ```json
   "ProcessName": "baseImage",        // Good
   "ProcessName": "fields[\"ProcessName\"]"  // Only if no normalized field exists
   ```

2. **Handle hash fields consistently**:
   ```json
   "MD5": "file_hash_md5",
   "SHA1": "file_hash_sha1", 
   "SHA256": "file_hash_sha256",
   "Hashes": "file_hash_sha256"  // Default to SHA256 for generic hash
   ```

3. **Map timestamps appropriately**:
   ```json
   "Timestamp": "timestamp",
   "EventTime": "timestamp",
   "UtcTime": "timestamp"
   ```

4. **Use consistent naming patterns**:
   ```json
   "SourceIP": "srcDevice_ip",
   "SrcIP": "srcDevice_ip",
   "src_ip": "srcDevice_ip"
   ```

### Example: Adding Cisco ASA Support

1. **Research**: Cisco ASA logs have fields like `src`, `dst`, `sport`, `dport`, `action`

2. **Create mapping file** (`field_mappings/network/cisco_asa.json`):
   ```json
   {
     "description": "Cisco ASA Firewall Logs",
     "logsource_conditions": [
       "metadata_vendor=\"Cisco\"",
       "metadata_product=\"ASA\""
     ],
     "field_mappings": {
       "src": "srcDevice_ip",
       "dst": "dstDevice_ip", 
       "sport": "srcPort",
       "dport": "dstPort",
       "action": "action",
       "protocol": "fields[\"protocol\"]",
       "user": "user_username"
     }
   }
   ```

3. **Create test rule** (`tests/fixtures/sample_rules/cisco_asa_test.yml`):
   ```yaml
   title: Cisco ASA Blocked Connection
   description: Test rule for Cisco ASA
   logsource:
     product: cisco
     service: asa
   detection:
     selection:
       action: denied
       dst: 192.168.1.100
     condition: selection
   ```

4. **Add test case** (`tests/test_cisco_asa.py`):
   ```python
   def test_cisco_asa_mapping(self):
       # Test the mapping functionality
       pass
   ```

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=sigma_sumo_converter

# Run specific test file
python -m pytest tests/test_converter.py

# Run with verbose output
python -m pytest -v
```

### Writing Tests

1. **Unit tests** for individual components
2. **Integration tests** for end-to-end conversion
3. **Fixture-based tests** using sample rules

Example test structure:
```python
def test_new_mapping(self):
    """Test new log source mapping"""
    logsource = {'product': 'newproduct', 'service': 'newservice'}
    mapped_field = self.field_mapper.map_field('sourceField', logsource)
    self.assertEqual(mapped_field, 'expectedField')
```

### Test Coverage Requirements

- **Minimum 85%** overall coverage
- **100%** coverage for new field mappings
- **Integration tests** for each new log source

## 📝 Code Quality Standards

### Code Formatting

We use several tools to maintain code quality:

```bash
# Format code with Black
black sigma_sumo_converter.py

# Sort imports with isort
isort sigma_sumo_converter.py

# Lint with flake8
flake8 sigma_sumo_converter.py

# Type checking with mypy
mypy sigma_sumo_converter.py
```

### Pre-commit Hooks

Pre-commit hooks automatically run quality checks:
- Trailing whitespace removal
- YAML/JSON validation
- Python formatting and linting
- Type checking

### Code Style Guidelines

1. **Follow PEP 8** Python style guide
2. **Use descriptive variable names**
3. **Add docstrings** to all functions and classes
4. **Include type hints** where possible
5. **Keep functions focused** and under 50 lines when possible

Example:
```python
def map_field(self, sigma_field: str, logsource: Dict[str, str] = None) -> str:
    """
    Map a Sigma field to Sumo Logic CSE normalized field.
    
    Args:
        sigma_field: The original Sigma field name
        logsource: The log source configuration
        
    Returns:
        The mapped Sumo Logic CSE field name
    """
    # Implementation here
```

## 📚 Documentation Standards

### README Updates

When adding new features:
1. **Update supported log sources table**
2. **Add example usage**
3. **Update installation instructions if needed**

### Inline Documentation

1. **Docstrings** for all public functions
2. **Comments** for complex logic
3. **Type hints** for function signatures

### Field Mapping Documentation

Document new mappings in `docs/field-mappings.md`:
```markdown
### New Product Name

| Sigma Field | CSE Field | Notes |
|-------------|-----------|-------|
| sourceField | targetField | Description |
```

## 🔄 Development Workflow

### Branch Naming

- `feature/description` - New features
- `bugfix/description` - Bug fixes  
- `mapping/product-name` - New field mappings
- `docs/description` - Documentation updates

### Commit Messages

Follow conventional commit format:
```
type(scope): description

Examples:
feat(mapping): add Cisco ASA firewall support
fix(converter): handle empty detection blocks
docs(readme): update installation instructions
test(integration): add AWS CloudTrail test cases
```

### Pull Request Process

1. **Create feature branch** from main
2. **Implement changes** with tests
3. **Update documentation**
4. **Run all tests** and quality checks
5. **Submit pull request** with clear description
6. **Address review feedback**
7. **Squash and merge** when approved

### Pull Request Template

Include:
- **Description** of changes
- **Type of change** (feature, bugfix, etc.)
- **Testing performed**
- **Field mapping details** (if applicable)
- **Documentation updates**
- **Breaking changes** (if any)

## 🐛 Bug Reports

### Before Reporting

1. **Search existing issues**
2. **Test with latest version**
3. **Reproduce the issue**
4. **Gather environment info**

### Bug Report Contents

Include:
- **Clear description** of the issue
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment details** (OS, Python version)
- **Sample Sigma rule** (sanitized)
- **Complete error message**

## ✨ Feature Requests

### Guidelines

1. **Check existing issues** first
2. **Provide clear use case**
3. **Include examples** when possible
4. **Consider implementation complexity**

### Feature Request Contents

- **Problem description**
- **Proposed solution**
- **Use case scenarios**
- **Example input/output**
- **Priority level**

## 🏆 Recognition

### Contributors

All contributors are recognized in:
- **README.md** contributors section
- **CHANGELOG.md** release notes
- **GitHub releases**

### Types of Recognition

- **Code contributors** - Pull requests merged
- **Issue reporters** - High-quality bug reports
- **Documentation** - Significant doc improvements
- **Field mappings** - New log source support
- **Testing** - Test coverage improvements

## 📞 Getting Help

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and general discussion
- **Pull Request Reviews** - Technical feedback

### Response Times

- **Bug reports**: Within 48 hours
- **Feature requests**: Within 1 week
- **Pull requests**: Within 1 week

## 📋 Checklist for Contributors

### Before Contributing

- [ ] Read this contributing guide
- [ ] Set up development environment
- [ ] Run existing tests successfully
- [ ] Understand the codebase structure

### For New Field Mappings

- [ ] Research log source thoroughly
- [ ] Create comprehensive mapping file
- [ ] Add test cases with sample rules
- [ ] Update documentation
- [ ] Test conversion end-to-end

### For Bug Fixes

- [ ] Reproduce the issue
- [ ] Write test case that fails
- [ ] Implement fix
- [ ] Verify test passes
- [ ] Check no regressions

### For Features

- [ ] Discuss in issue first
- [ ] Design with extensibility in mind
- [ ] Add comprehensive tests
- [ ] Update documentation
- [ ] Consider backward compatibility

### Before Submitting PR

- [ ] All tests pass
- [ ] Code formatted with Black
- [ ] No linting errors
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] PR description complete

## 🤝 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors regardless of background, experience level, or identity.

### Expected Behavior

- **Be respectful** and professional
- **Provide constructive feedback**
- **Focus on the code**, not the person
- **Help newcomers** get started
- **Acknowledge contributions**

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or inflammatory comments
- Personal attacks
- Publishing private information

### Reporting

Report any issues to the project maintainers through private communication channels.

---

Thank you for contributing to the Sigma to Sumo Logic CSE Converter! Your contributions help make security detection engineering more efficient and effective for the entire community. 🎉