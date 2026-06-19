# ============================================================================
# cmake/Tests.cmake -- register the heavybag test harnesses as CTest tests.
#
# The portable entry point for the QA test-matrix campaign (docs/qa-campaign.md).
# Each test is a THIN CTest wrapper around the committed bash harness under
# modules/ngx_http_heavybag/tests/ -- the harness stays the single source of
# truth, CMake/CTest is just the portable launcher (pass/fail summary, labels,
# parallelism, JUnit/XML export for CI, timeouts).
#
# Usage (after a normal build produces the sandbox nginx + deployed .so):
#     cmake --build build -j
#     ctest --test-dir build                 # run everything
#     ctest --test-dir build -L integration  # only the live-nginx harnesses
#     ctest --test-dir build -L unit         # only the standalone unit suite
#     ctest --test-dir build -R config       # by name regex
#     ctest --test-dir build -j8             # parallel (nginx-bound tests are
#                                            #   still serialised by a resource lock)
#   or the convenience wrapper:
#     cmake --build build --target check
#
# A harness that exits 2 (its preflight detected the sandbox is not built yet)
# is reported by CTest as SKIPPED, not failed -- so `ctest` before `cmake --build`
# is harmless. The unit + build-matrix tests do not need a running nginx; the
# rest load the deployed sandbox/modules/.so against a live master they start on
# loopback-only 28xxx ports.
# ============================================================================

find_program(BASH_PROGRAM bash)
if(NOT BASH_PROGRAM)
  message(WARNING "bash not found -- heavybag CTest harnesses will NOT be registered")
  return()
endif()

set(_HB_TESTS ${CMAKE_SOURCE_DIR}/modules/ngx_http_heavybag/tests)

# heavybag_add_test(<name> <script-rel-to-tests-dir>
#                   [TIMEOUT <seconds>] [LABELS <l1;l2>] [NGINX_BOUND])
#
# NGINX_BOUND tests start a real nginx master on fixed ports and share the
# sandbox .so/logs, so they take a RESOURCE_LOCK and never run concurrently
# with each other (even under `ctest -jN`).
function(heavybag_add_test name script)
  cmake_parse_arguments(T "NGINX_BOUND" "TIMEOUT" "LABELS;ENV" ${ARGN})
  if(NOT EXISTS ${_HB_TESTS}/${script})
    message(WARNING "heavybag test harness missing, skipping registration: ${script}")
    return()
  endif()
  if(NOT T_TIMEOUT)
    set(T_TIMEOUT 600)
  endif()
  # make the harnesses relocatable: they read ROOT from this env (falling back
  # to the historical /mnt path when run by hand without it). Extra per-test ENV
  # (e.g. LIMIT for the replay sweep) is appended to the same property list.
  set(_env "HEAVYBAG_ROOT=${CMAKE_SOURCE_DIR}")
  if(T_ENV)
    list(APPEND _env ${T_ENV})
  endif()
  add_test(NAME ${name}
           COMMAND ${BASH_PROGRAM} ${_HB_TESTS}/${script}
           WORKING_DIRECTORY ${_HB_TESTS})
  set_tests_properties(${name} PROPERTIES
    LABELS           "${T_LABELS}"
    TIMEOUT          ${T_TIMEOUT}
    SKIP_RETURN_CODE 2
    ENVIRONMENT      "${_env}")
  if(T_NGINX_BOUND)
    set_tests_properties(${name} PROPERTIES RESOURCE_LOCK heavybag_sandbox)
  endif()
endfunction()

# --- standalone unit suite (compiles its own gcc binaries, no nginx) ---------
heavybag_add_test(heavybag_unit         unit/run-unit-tests.sh  LABELS "unit"                TIMEOUT 600)

# --- build-portability matrix (rebuilds the ./configure permutation trees) ---
heavybag_add_test(heavybag_build_matrix run-build-matrix.sh     LABELS "build"               TIMEOUT 1800)

# --- live-nginx integration + runtime (need the built sandbox + deployed .so) -
heavybag_add_test(heavybag_config       run-config-tests.sh     LABELS "integration;config"  TIMEOUT 600  NGINX_BOUND)
heavybag_add_test(heavybag_protocol     run-protocol-tests.sh   LABELS "integration"         TIMEOUT 600  NGINX_BOUND)
heavybag_add_test(heavybag_stat         run-stat-tests.sh       LABELS "integration"         TIMEOUT 900  NGINX_BOUND)
heavybag_add_test(heavybag_regression   run-regression-tests.sh LABELS "integration"         TIMEOUT 600  NGINX_BOUND)
heavybag_add_test(heavybag_runtime      run-runtime-tests.sh    LABELS "integration;runtime" TIMEOUT 600  NGINX_BOUND)

# --- detect-mode replay (FP gate is the pass/fail; coverage sweep capped) -----
# Exit 0 iff the false-positive gate holds (every baseline path returns reason=none
# and all would_block deltas are 0); the main coverage replay is bounded by LIMIT.
heavybag_add_test(heavybag_replay       run-replay-tests.sh     LABELS "integration;replay"  TIMEOUT 900  NGINX_BOUND  ENV "LIMIT=200")

# --- honeypot-D offline ASN/geo analysis (no nginx; SKIPs if inputs absent) ---
# Pure read-only analysis pipeline: builds reference/geolookup.c, extracts the
# per-IP volume feed, joins it with geo. Exits 2 (-> CTest SKIPPED) when the raw
# access log / geo db are not present on this host.
heavybag_add_test(heavybag_honeypot     run-honeypot-d.sh       LABELS "analysis"            TIMEOUT 600)

# --- reference-oracle build smoke (compiles reference/*.c; asserts no behaviour)
heavybag_add_test(heavybag_oracle_build run-oracle-build.sh     LABELS "build"               TIMEOUT 300)

# --- convenience: `cmake --build build --target check` == ctest --------------
add_custom_target(check
  COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --test-dir ${CMAKE_BINARY_DIR}
  COMMENT "Running the heavybag CTest suite (ctest --output-on-failure)")
