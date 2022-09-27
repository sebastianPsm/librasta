#pragma once

#include <CUnit/Basic.h>

// include tests
#include "sciTests.h"
#include "scilsTests.h"
#include "scipTests.h"
/*
 * Called by the Gradle CUnit launcher to register all CUnit tests.
 */
void gradle_cunit_register();
