#include <stddef.h>
#include "picotls.h"

#define LAYOUT_ASSERT_JOIN_(a, b) a##b
#define LAYOUT_ASSERT_JOIN(a, b) LAYOUT_ASSERT_JOIN_(a, b)
#define LAYOUT_ASSERT_EQ(a, b) \
    typedef char LAYOUT_ASSERT_JOIN(layout_assertion_, __LINE__)[((a) == (b)) ? 1 : -1]

LAYOUT_ASSERT_EQ(offsetof(ptls_iovec_t, base), 0);
LAYOUT_ASSERT_EQ(offsetof(ptls_iovec_t, len), sizeof(void *));
