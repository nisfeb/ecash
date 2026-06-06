# ecash mint — development helpers
#
# Prerequisites:
#   npm install              (one-time, installs @noble/secp256k1 etc.)
#   Fake zod running on localhost:8080 with %ecash desk installed
#
# For Lightning tests, also need mock LNbits running:
#   make mock-lnbits         (runs in foreground)
#   Configure mint: :ecash [%lnbits 'http://localhost:3338' 'test-api-key']

.PHONY: test test-p2pk test-cred test-lightning test-all mock-lnbits install deploy test-security test-conformance sync-libs

# Shared crypto: desk/lib is the single source of truth; regenerate the
# %ecash-services copies from it (they are gitignored). Run before building
# the %ecash-services desk.
sync-libs:
	cp desk/lib/curve.hoon desk/lib/bdhke.hoon desk-services/lib/

# Run core tests (no Lightning required)
test: test-p2pk test-cred

# Individual test suites
test-p2pk:
	node test-p2pk.mjs

test-cred:
	node test-cred.mjs

test-lightning:
	node test-lightning.mjs

# Run everything (Lightning tests require mock-lnbits running separately)
test-all: test-p2pk test-cred test-lightning

# Start mock LNbits server on port 3338
mock-lnbits:
	node mock-lnbits.mjs

# Install npm dependencies
install:
	npm install

# Phase 1 security regression (set URBAUTH_COOKIE for the authenticated paths)
test-security:
	node test-admin-auth.mjs
	node test-legacy-removed.mjs
	node test-parse-robustness.mjs
	node test-self-method.mjs
	node test-swap-security.mjs

# Phase 2 wallet conformance (needs mock-lnbits running + URBAUTH_COOKIE)
test-conformance:
	node test-conformance.mjs

# Copy desk files to mounted Clay desk and commit
# Assumes zod is mounted at ./zod/ecash/
deploy:
	cp -r desk/* zod/ecash/
