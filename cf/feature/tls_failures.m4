divert(-1)
#
# Copyright (c) 2015 Proofpoint, Inc. and its suppliers.
#	All rights reserved.
#
# By using this file, you agree to the terms and conditions set
# forth in the LICENSE file which can be found at the top level of
# the sendmail distribution.
#
#

divert(-1)

define(`_TLS_FAILURES_', `1')dnl
define(`_NEED_MACRO_MAP_', `1')dnl
define(`_TLS_FAILURES_CNT_', ifelse(len(X`'_ARG_), `1', `5', _ARG_)))dnl

LOCAL_CONFIG
C{persistentMacros}{saved_verify}
