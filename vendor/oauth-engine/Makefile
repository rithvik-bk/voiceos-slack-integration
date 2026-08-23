# HANDSHAKE — one-command verification gate (the engine's Definition-of-Done).
#
#   make verify
#
# Green from a CLEAN CHECKOUT means the engine's whole contract holds: it builds, it
# type-checks, every test (invariants included) passes, it ships zero runtime dependencies,
# no secret-shaped string is in the tree, and no engine file branches on a provider name.
#
# Ordering is deliberate: the CHEAP gates run first so a broken invariant or a leaked secret
# fails in about a second, and the ~18s full test suite runs last. Any single gate failing
# stops `verify` with a non-zero exit — there is no "mostly green".
#
# Node runs TypeScript natively (engine contract §A2): there is no emit step, so "build" is a
# real smoke test that the engine's entire module graph type-strips and loads under node, and
# "typecheck" is the full `tsc --noEmit` type build. Every target is independently runnable.
#
# The ENGINE ships zero RUNTIME dependencies; the two build-time tools (TypeScript + vitest) are
# devDependencies. Every gate that needs them depends on `deps`, which installs them from the
# lockfile the first time only. This is why `make verify` and `make demo` are green from a truly
# cold clone: the toolchain is resolved from node_modules, never from the network, so the gates
# can never fall through to the unrelated remote `tsc` package.

NODE ?= node
NPM ?= npm
BIN := node_modules/.bin
VITEST ?= $(BIN)/vitest run
TSC ?= $(BIN)/tsc --noEmit -p tsconfig.json
GUARD_NO_BRANCH := engine/test/guard-no-provider-branch.test.ts
GUARD_NO_SECRET := engine/test/scan-secrets.test.ts engine/test/guard-no-secret-in-build.test.ts
GUARD_INVARIANTS := $(GUARD_NO_BRANCH) engine/test/guard-no-secret-in-build.test.ts

.PHONY: verify deps build typecheck test invariants zero-dep no-secret-leak no-per-provider-branch demo clean help

## verify: the full gate — build + typecheck + invariants + zero-dep + no-secret-leak + no-per-provider-branch + full tests
verify: deps build typecheck zero-dep no-secret-leak no-per-provider-branch invariants test
	@echo ""
	@echo "verify: ALL GATES GREEN — build · typecheck · invariants · zero-dep · no-secret-leak · no-per-provider-branch · full suite"

## deps: ensure the build-time toolchain (TypeScript + vitest) is installed — required from a cold
## clone, where otherwise `npx tsc` resolves the unrelated remote `tsc` package and fails cryptically.
deps:
	@[ -x "$(BIN)/tsc" ] && [ -x "$(BIN)/vitest" ] || { echo "── deps: installing the build-time toolchain (npm ci) ──"; $(NPM) ci; }

## build: prove the engine's whole module graph type-strips and loads under node-native TS
build:
	@echo "── build: loading the engine module graph under node-native TypeScript ──"
	@$(NODE) --input-type=module -e "await import('./engine/src/index.ts'); console.log('build OK: engine module graph loads, imports resolve, types erase');"

## typecheck: the full tsc type build (no emit — node strips types at runtime)
typecheck: deps
	@echo "── typecheck: tsc --noEmit over engine + tools + relay ──"
	@$(TSC)

## test: the full test suite (invariant, guard, and unit tests together)
test: deps
	@echo "── test: full vitest suite ──"
	@$(VITEST)

## invariants: the G1 contract-lock guards (INV-CONFIG-1/2/3/4, INV-SECRET-1/4)
invariants: deps
	@echo "── invariants: contract-lock guards ──"
	@$(VITEST) $(GUARD_INVARIANTS)

## zero-dep: assert the engine ships NO runtime dependencies (INV-REL-1)
zero-dep:
	@echo "── zero-dep: package.json has no runtime dependencies ──"
	@$(NODE) -e "const p=require('./package.json'); const d=p.dependencies&&Object.keys(p.dependencies).length; if(d){console.error('FAIL: '+d+' runtime dependency(ies) present');process.exit(1);} console.log('zero-dep OK: no runtime dependencies');"

## no-secret-leak: the push-gate secret scan over the source tree + its guard tests (INV-SECRET-1/4)
no-secret-leak: deps
	@echo "── no-secret-leak: scan-secrets over the tree + redaction/build-output guards ──"
	@$(NODE) tools/scan-secrets.mjs
	@$(VITEST) $(GUARD_NO_SECRET)

## no-per-provider-branch: assert zero `if (provider === …)` in engine/src (INV-CONFIG-1)
no-per-provider-branch: deps
	@echo "── no-per-provider-branch: INV-CONFIG-1 guard ──"
	@$(VITEST) $(GUARD_NO_BRANCH)

## demo: run the end-to-end demo against the built-in mock provider (zero external registration)
demo:
	@echo "── demo: real engine · real HTTP OAuth · built-in mock provider ──"
	@$(NODE) tools/demo.mjs

## help: list the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
