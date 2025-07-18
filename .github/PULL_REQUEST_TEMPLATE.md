# Pull Request

## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Field mapping addition/update
- [ ] Performance improvement
- [ ] Code refactoring

## Changes Made
- [ ] Added/modified field mappings for: ___________
- [ ] Fixed conversion logic for: ___________
- [ ] Updated documentation
- [ ] Added tests
- [ ] Other: ___________

## Testing
- [ ] Added unit tests for new functionality
- [ ] Existing tests pass
- [ ] Tested with sample Sigma rules
- [ ] Manual testing performed

### Test Results
```bash
# Paste test output here
```

## Field Mapping Changes (if applicable)
If this PR adds or modifies field mappings, please provide:

**Log Source:** [e.g. Windows/Sysmon, AWS/CloudTrail]
**New Fields Added:**
- `sigma_field` → `sumo_cse_field`
- `another_field` → `mapped_field`

**Sample Conversion:**
```yaml
# Input Sigma rule snippet
```
```json
// Expected CSE output
```

## Documentation
- [ ] Updated README.md if needed
- [ ] Updated field mapping documentation
- [ ] Added examples
- [ ] Updated CHANGELOG.md

## Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Additional Notes
Any additional information, considerations, or context for reviewers.

## Related Issues
Closes #[issue_number]
Related to #[issue_number]

## Screenshots (if applicable)
Add screenshots to help explain your changes.

## Deployment Notes
Any special deployment considerations, migration steps, or breaking changes to note.
