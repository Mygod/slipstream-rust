use slipstream_core::test_support::FailureCounter;

pub(super) const FORCED_ADD_TO_STREAM_ERROR: i32 = -1;
pub(super) const FORCED_MARK_ACTIVE_STREAM_ERROR: i32 = 0x400 + 36;
pub(super) static ADD_TO_STREAM_FAILS_LEFT: FailureCounter = FailureCounter::new();
pub(super) static MARK_ACTIVE_STREAM_FAILS_LEFT: FailureCounter = FailureCounter::new();

pub(super) fn set_add_to_stream_failures(count: usize) {
    ADD_TO_STREAM_FAILS_LEFT.set(count);
}

pub(super) fn set_mark_active_stream_failures(count: usize) {
    MARK_ACTIVE_STREAM_FAILS_LEFT.set(count);
}

pub(super) fn take_add_to_stream_failure() -> bool {
    ADD_TO_STREAM_FAILS_LEFT.take()
}

pub(super) fn take_mark_active_stream_failure() -> bool {
    MARK_ACTIVE_STREAM_FAILS_LEFT.take()
}
