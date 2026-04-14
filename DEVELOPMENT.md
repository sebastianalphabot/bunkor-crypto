# Development Guide

Instructions for testing, building, and publishing updates to @bunkor/crypto.

## Setup Development Environment

```bash
cd packages/crypto
npm install
```

## Running Tests

Run all tests:
```bash
npm test
```

Run tests in watch mode:
```bash
npm test -- --watch
```

Run tests with coverage:
```bash
npm test -- --coverage
```

## Building

Build TypeScript to JavaScript:
```bash
npm run build
```

Output goes to `dist/` directory.

## Linting

Check code style:
```bash
npm run lint
```

## Publishing Updates to npm

### Step 1: Make Changes

Edit source files in `src/`. Update documentation in markdown files.

### Step 2: Run Tests

```bash
npm test
```

Ensure all tests pass before publishing.

### Step 3: Build

```bash
npm run build
```

### Step 4: Update Version

Update version in `package.json`:

```bash
# Patch version (0.1.0 → 0.1.1)
npm version patch

# Minor version (0.1.0 → 0.2.0)
npm version minor

# Major version (0.1.0 → 1.0.0)
npm version major
```

This automatically creates a git tag and commits the version change.

### Step 5: Update CHANGELOG (Optional)

Create or update `CHANGELOG.md` with version history:

```markdown
## [0.1.1] - 2026-04-14

### Fixed
- Bug fix description

### Added
- New feature description

## [0.1.0] - 2026-04-14

### Initial Release
- Core cryptographic services
- Bunkor integration
- Complete documentation
```

### Step 6: Commit Changes

```bash
git add -A
git commit -m "chore: version bump to 0.1.1

- Fix: Description
- Feature: Description"
```

### Step 7: Push to GitHub

```bash
git push origin main
git push origin --tags
```

### Step 8: Publish to npm

```bash
npm publish --access public
```

Verify on npm:
```bash
npm view @bunkor/crypto
```

## Version Strategy

Follow Semantic Versioning (MAJOR.MINOR.PATCH):

- **MAJOR** (1.0.0): Breaking changes to API
- **MINOR** (0.1.0): New features, backward compatible
- **PATCH** (0.0.1): Bug fixes, backward compatible

## Continuous Integration (Optional)

For automated testing, create `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: 18
      - run: npm install
      - run: npm test
      - run: npm run build
```

## Rollback if Needed

If you need to unpublish a version (within 72 hours):

```bash
npm unpublish @bunkor/crypto@0.1.1
```

## File Structure for Distribution

The npm package includes:
- `dist/` - Compiled JavaScript and type definitions
- `README.md` - Package documentation
- `LICENSE` - Apache 2.0 license
- `package.json` - Package metadata

Excluded from npm (in `.npmignore`):
- `src/` - Source TypeScript files
- `*.spec.ts` - Test files
- `.git/` - Git metadata
- `tsconfig.json` - TypeScript config

## Security

- Never commit npm tokens to git
- Use environment variables for sensitive data
- Keep dependencies updated: `npm audit`
- Rotate npm tokens periodically
