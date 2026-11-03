package main

// The standard formats are adapter modules of CTIS 2.0: importing one
// registers it with the importer, so `upload` detects and checks it. A
// format whose adapter is not imported here is not accepted.
import (
	_ "github.com/openctemio/ctis/v2/interop/csaf"
	_ "github.com/openctemio/ctis/v2/interop/cyclonedx"
	_ "github.com/openctemio/ctis/v2/interop/openvex"
	_ "github.com/openctemio/ctis/v2/interop/sarif"
	_ "github.com/openctemio/ctis/v2/interop/spdx"
)
