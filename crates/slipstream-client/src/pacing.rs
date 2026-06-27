use slipstream_ffi::picoquic::picoquic_path_quality_t;

// Pacing gain tuning for the poll-based pacing loop.
pub(crate) const DEFAULT_PACING_GAIN_PROBE: f64 = 1.4;
const PACING_GAIN_BASE: f64 = 1.0;
const PACING_GAIN_EPSILON: f64 = 0.05;
const PACING_GAIN_PROBE_MIN: f64 = 1.0;
const PACING_GAIN_PROBE_MAX: f64 = 4.0;
const MIN_AUTHORITATIVE_TARGET_INFLIGHT: usize = 64;
const MAX_AUTHORITATIVE_TARGET_INFLIGHT: usize = 768;
const MIN_AUTHORITATIVE_INFLIGHT_BYTES: usize = 96 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PacingBudgetSnapshot {
    pub(crate) pacing_rate: u64,
    pub(crate) qps: f64,
    pub(crate) gain: f64,
    pub(crate) target_inflight: usize,
}

pub(crate) struct PacingPollBudget {
    payload_bytes: f64,
    mtu: u32,
    last_pacing_rate: u64,
    probe_gain: f64,
}

impl PacingPollBudget {
    pub(crate) fn new(mtu: u32, probe_gain: f64) -> Self {
        debug_assert!(mtu > 0, "PacingPollBudget::new expects MTU > 0");
        Self {
            payload_bytes: mtu.max(1) as f64,
            mtu,
            last_pacing_rate: 0,
            probe_gain: sanitize_pacing_gain_probe(probe_gain),
        }
    }

    pub(crate) fn target_inflight(
        &mut self,
        quality: &picoquic_path_quality_t,
        rtt_proxy_us: u64,
    ) -> PacingBudgetSnapshot {
        let pacing_rate = quality.pacing_rate;
        let rtt_seconds = (self.derive_rtt_us(quality.rtt, rtt_proxy_us) as f64) / 1_000_000.0;
        if pacing_rate == 0 {
            let target_inflight = clamp_authoritative_target_for_mtu(
                cwnd_target_polls(quality.cwin, self.mtu),
                self.mtu,
            );
            let qps = target_inflight as f64 / rtt_seconds;
            self.last_pacing_rate = 0;
            return PacingBudgetSnapshot {
                pacing_rate,
                qps,
                gain: PACING_GAIN_BASE,
                target_inflight,
            };
        }

        let gain = self.next_gain(pacing_rate);
        let qps = (pacing_rate as f64 / self.payload_bytes) * gain;
        let target_inflight = clamp_authoritative_target_for_mtu(
            (qps * rtt_seconds).ceil().min(usize::MAX as f64) as usize,
            self.mtu,
        );

        PacingBudgetSnapshot {
            pacing_rate,
            qps,
            gain,
            target_inflight,
        }
    }

    fn derive_rtt_us(&self, rtt_us: u64, rtt_proxy_us: u64) -> u64 {
        let candidate = if rtt_us > 0 { rtt_us } else { rtt_proxy_us };
        // Clamp to 1us to avoid divide-by-zero when RTT is unknown.
        candidate.max(1)
    }

    fn next_gain(&mut self, pacing_rate: u64) -> f64 {
        let gain =
            if pacing_rate as f64 > (self.last_pacing_rate as f64) * (1.0 + PACING_GAIN_EPSILON) {
                self.probe_gain
            } else {
                PACING_GAIN_BASE
            };
        self.last_pacing_rate = pacing_rate;
        gain
    }
}

fn clamp_authoritative_target_for_mtu(target: usize, mtu: u32) -> usize {
    let mtu = mtu.max(1) as usize;
    let mtu_floor = MIN_AUTHORITATIVE_INFLIGHT_BYTES.div_ceil(mtu);
    target
        .max(MIN_AUTHORITATIVE_TARGET_INFLIGHT)
        .max(mtu_floor)
        .min(MAX_AUTHORITATIVE_TARGET_INFLIGHT)
}

pub(crate) fn sanitize_pacing_gain_probe(value: f64) -> f64 {
    if value.is_finite() && value >= PACING_GAIN_PROBE_MIN {
        value.min(PACING_GAIN_PROBE_MAX)
    } else {
        DEFAULT_PACING_GAIN_PROBE
    }
}

pub(crate) fn cwnd_target_polls(cwin: u64, mtu: u32) -> usize {
    debug_assert!(mtu > 0, "mtu must be > 0");
    let mtu = mtu as u64;
    if mtu == 0 {
        return 0;
    }
    let target = cwin.saturating_add(mtu - 1) / mtu;
    usize::try_from(target).unwrap_or(usize::MAX)
}

pub(crate) fn inflight_packet_estimate(bytes_in_transit: u64, mtu: u32) -> usize {
    debug_assert!(mtu > 0, "mtu must be > 0");
    let mtu = mtu as u64;
    if mtu == 0 {
        return 0;
    }
    let packets = bytes_in_transit.saturating_add(mtu - 1) / mtu;
    if packets > usize::MAX as u64 {
        usize::MAX
    } else {
        packets as usize
    }
}
