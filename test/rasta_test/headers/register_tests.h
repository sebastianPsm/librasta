#pragma once

#include <CUnit/Basic.h>

// INCLUDE TESTS
#include "rastamd4_test.h"
#include "rastamodule_test.h"
/*
 * Called by the Gradle CUnit launcher to register all CUnit tests.
 */
void gradle_cunit_register();
