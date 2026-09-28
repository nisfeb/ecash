# ecash mint — development helpers
#
# Tests: `npm install` once, then point them at a ship running %ecash and
# %ecash-services (run-tests.mjs says what each suite needs):
#   SHIP_URL=http://localhost:8080 URBAUTH_COOKIE='urbauth-~zod=0v…' make test
#   make test-p2pk           (one suite: npm run test:p2pk)
# The Lightning suites start their own mock LNbits; `make mock-lnbits` runs
# one in the foreground for the demo.

.PHONY: test mock-lnbits install deploy sync-libs hoon-test

# Shared crypto: desk/lib is the single source of truth; regenerate the
# %ecash-services copies from it (they are gitignored). Run before building
# the %ecash-services desk.
sync-libs:
	mkdir -p desk-services/lib
	cp desk/lib/curve.hoon desk/lib/bdhke.hoon desk/lib/ecash-http.hoon desk-services/lib/

# Every release-gating suite (npm run test:all), or one: make test-<suite>
test:
	npm run test:all

test-%:
	npm run test:$*

# Mock LNbits on port 3338, in the foreground
mock-lnbits:
	npm run mock:lnbits

# Install npm dependencies
install:
	npm install

# Build both desks and copy them into mounted desks, then |commit each in
# the ship's dojo. build.sh brings the base-dev deps and wipes the target,
# refusing a directory with no sys.kelvin:
#   make deploy PIER=/path/to/pier
deploy:
	@test -n "$(PIER)" || { echo "usage: make deploy PIER=/path/to/pier" >&2; exit 1; }
	./build.sh -p $(PIER)/ecash
	./build.sh services -p $(PIER)/ecash-services

# Hoon unit suites on a fake ship's %ecash-test desk (see docs/hoon-testing.md)
hoon-test:
	@test -n "$(PIER)" || { echo "usage: make hoon-test PIER=/path/to/pier" >&2; exit 1; }
	scripts/hoon-test-kit/hoon-test.sh $(PIER)
