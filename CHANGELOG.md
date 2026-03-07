# Changelog

## v0.0.7

[compare changes](https://github.com/sandros94/unsecure/compare/v0.0.6...v0.0.7)

### 🚀 Enhancements

- New `randomJitter` utility ([06980e2](https://github.com/sandros94/unsecure/commit/06980e2))

### 🔥 Performance

- Implement buffer detection and enhance base64/hex utilities ([42077b4](https://github.com/sandros94/unsecure/commit/42077b4))

### 💅 Refactors

- Simplify sanitizeObject and remove redundant key deletion strategies ([7ebe13b](https://github.com/sandros94/unsecure/commit/7ebe13b))

### 📖 Documentation

- Update examples for random utils ([b59202a](https://github.com/sandros94/unsecure/commit/b59202a))
- **random:** Properly document when utils throw ([1166297](https://github.com/sandros94/unsecure/commit/1166297))

### 🏡 Chore

- Switch to oxc and tsgo, update deps ([272bef0](https://github.com/sandros94/unsecure/commit/272bef0))
- Add `AGENT.md` ([9451c91](https://github.com/sandros94/unsecure/commit/9451c91))
- Add claude settings ([77ccc0d](https://github.com/sandros94/unsecure/commit/77ccc0d))
- Update readme badges ([0cf5dfd](https://github.com/sandros94/unsecure/commit/0cf5dfd))

### 🤖 CI

- Refactor workflows ([321f72a](https://github.com/sandros94/unsecure/commit/321f72a))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.6

[compare changes](https://github.com/sandros94/unsecure/compare/v0.0.5...v0.0.6)

### 🚀 Enhancements

- Enhance secure random number generation with range and ignore options ([b261599](https://github.com/sandros94/unsecure/commit/b261599))

### 📖 Documentation

- Document timestamp usage for `secureGenerate` ([76bc93f](https://github.com/sandros94/unsecure/commit/76bc93f))

### 📦 Build

- Switch to obuild ([22df20f](https://github.com/sandros94/unsecure/commit/22df20f))
- Add rolldown platform configuration ([7e9a4a8](https://github.com/sandros94/unsecure/commit/7e9a4a8))

### 🏡 Chore

- Apply automated updates ([4cd42ec](https://github.com/sandros94/unsecure/commit/4cd42ec))
- Update gitignore ([bd33548](https://github.com/sandros94/unsecure/commit/bd33548))

### 🤖 CI

- Unify jobs and run autofix only when required ([501a99c](https://github.com/sandros94/unsecure/commit/501a99c))
- Update workflows ([61af225](https://github.com/sandros94/unsecure/commit/61af225))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.5

[compare changes](https://github.com/sandros94/unsecure/compare/v0.0.4...v0.0.5)

### 🚀 Enhancements

- Add timestamp option to secureGenerate for time-sortable tokens ([6b2fcdb](https://github.com/sandros94/unsecure/commit/6b2fcdb))

### 📖 Documentation

- Describe `sanitizeObject` utility ([230ebb7](https://github.com/sandros94/unsecure/commit/230ebb7))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.4

[compare changes](https://github.com/sandros94/unsecure/compare/v0.0.3...v0.0.4)

### 🚀 Enhancements

- Sanitizing utility for prototype pollution ([0d48bff](https://github.com/sandros94/unsecure/commit/0d48bff))

### 🏡 Chore

- Add vscode tasks ([2b9856f](https://github.com/sandros94/unsecure/commit/2b9856f))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.3

[compare changes](https://github.com/sandros94/unsecure/compare/v0.0.2...v0.0.3)

### 💅 Refactors

- Rename `secureVerify` to `secureCompare` ([1773c93](https://github.com/sandros94/unsecure/commit/1773c93))
- Rename `generateSecurePassword` to `secureGenerate` ([bf131f6](https://github.com/sandros94/unsecure/commit/bf131f6))

### 📖 Documentation

- **hash:** Document `returnAs` option ([027e103](https://github.com/sandros94/unsecure/commit/027e103))

### 🏡 Chore

- Update deps ([8ec53e1](https://github.com/sandros94/unsecure/commit/8ec53e1))

### ✅ Tests

- **hash:** Add throwing test ([db61274](https://github.com/sandros94/unsecure/commit/db61274))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.2

[compare changes](https://github.com/sandros94/unsecure/compare/v0.0.1...v0.0.2)

### 🩹 Fixes

- **hash:** Optionally return base64/base64url encoded strings ([fe98972](https://github.com/sandros94/unsecure/commit/fe98972))

### 📖 Documentation

- Readme typo ([7e31c50](https://github.com/sandros94/unsecure/commit/7e31c50))

### 🏡 Chore

- Apply automated updates ([796cc19](https://github.com/sandros94/unsecure/commit/796cc19))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))

## v0.0.1

### 🚀 Enhancements

- Base64 utils ([660ec61](https://github.com/sandros94/unsecure/commit/660ec61))
- **utils:** Hex encoding/decoding ([af548ba](https://github.com/sandros94/unsecure/commit/af548ba))
- Hashing util ([9b6fb90](https://github.com/sandros94/unsecure/commit/9b6fb90))
- Verify util (timing attacks) ([db1580e](https://github.com/sandros94/unsecure/commit/db1580e))
- **password:** Re-export as `generateSecureToken` ([8fdc86a](https://github.com/sandros94/unsecure/commit/8fdc86a))

### 🩹 Fixes

- **utils:** Base64 ([eb5da3e](https://github.com/sandros94/unsecure/commit/eb5da3e))
- Missing export ([0361c76](https://github.com/sandros94/unsecure/commit/0361c76))
- **utils:** Hex encoding ([9acfa0f](https://github.com/sandros94/unsecure/commit/9acfa0f))
- Missing export ([bc56dc6](https://github.com/sandros94/unsecure/commit/bc56dc6))
- **secureVerify:** Error if reference is nullish ([e1119ba](https://github.com/sandros94/unsecure/commit/e1119ba))

### 💅 Refactors

- **password:** Improve performance with factory utility ([06d1b2d](https://github.com/sandros94/unsecure/commit/06d1b2d))

### 📖 Documentation

- Init readme ([f2d9be8](https://github.com/sandros94/unsecure/commit/f2d9be8))
- Document `createSecureRandomGenerator` ([570011d](https://github.com/sandros94/unsecure/commit/570011d))

### 🏡 Chore

- Init ([7f65b8a](https://github.com/sandros94/unsecure/commit/7f65b8a))
- Remove `*.d.ts` from final build ([d751b87](https://github.com/sandros94/unsecure/commit/d751b87))

### ✅ Tests

- Add base64 and hex ([f7132c0](https://github.com/sandros94/unsecure/commit/f7132c0))

### ❤️ Contributors

- Sandro Circi ([@sandros94](https://github.com/sandros94))
