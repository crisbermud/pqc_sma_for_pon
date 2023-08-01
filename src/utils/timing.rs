use cpu_time::ProcessTime;
use quantogram::Quantogram;
use rand::CryptoRng;
use rand::RngCore;

/// Tracked metrics for one run
#[derive(Debug, Default)]
pub struct Metric {
    time_cpu: std::time::Duration,
    time_total: std::time::Duration,
    random_bytes: usize,
}

impl std::ops::AddAssign for Metric {
    fn add_assign(&mut self, rhs: Self) {
        self.time_cpu += rhs.time_cpu;
        self.time_total += rhs.time_total;
        self.random_bytes += rhs.random_bytes;
    }
}

impl std::ops::Sub for Metric {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            time_cpu: self.time_cpu - rhs.time_cpu,
            time_total: self.time_total - rhs.time_total,
            random_bytes: self.random_bytes - rhs.random_bytes,
        }
    }
}

impl Metric {
    /// Get the current value of a metric. Only meaningful if subtracted from another result of now()
    pub fn now(rng: &CountingRng<impl RngCore>) -> Self {
        Self {
            time_cpu: ProcessTime::now().as_duration(),
            time_total: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap(),
            random_bytes: rng.bytes_generated(),
        }
    }

    /// Get elapsed metric counts since the given result of now()
    pub fn elapsed(self, rng: &CountingRng<impl RngCore>) -> Self {
        return Self::now(rng) - self;
    }
}

// Accumulated metrics over several runs using the Quantogram library
#[derive(Debug)]
pub struct MetricAccumulation {
    time_cpu_ms: Quantogram,
    time_total_ms: Quantogram,
    random_bytes: Quantogram,
}

impl std::ops::AddAssign<Metric> for MetricAccumulation {
    fn add_assign(&mut self, rhs: Metric) {
        self.time_cpu_ms.add(rhs.time_cpu.as_secs_f64() * 1e3);
        self.time_total_ms.add(rhs.time_total.as_secs_f64() * 1e3);
        self.random_bytes.add(rhs.random_bytes as f64);
    }
}

impl Default for MetricAccumulation {
    fn default() -> Self {
        Self {
            time_cpu_ms: Quantogram::new(),
            time_total_ms: Quantogram::new(),
            random_bytes: Quantogram::new(),
        }
    }
}

/// Generate relevant values for a box plot as tab seperated string
fn boxplot(q: &Quantogram) -> String {
    return format!(
        "{}\t{}\t{}\t{}\t{}",
        q.min().unwrap(),
        q.q1().unwrap(),
        q.median().unwrap(),
        q.q3().unwrap(),
        q.max().unwrap(),
    );
}

impl MetricAccumulation {
    /// get boxplot values with given prefix and metric name as tab seperated strings
    pub fn stats(&self, prefix: &str) -> Vec<String> {
        return vec![
            format!("{}\ttime_cpu_ms\t{}", prefix, boxplot(&self.time_cpu_ms)),
            format!(
                "{}\ttime_total_ms\t{}",
                prefix,
                boxplot(&self.time_total_ms)
            ),
            format!("{}\trandom_bytes\t{}", prefix, boxplot(&self.random_bytes)),
        ];
    }
}

/// count metrics for the given get + set operation combination on a pair of OLT and ONU
#[inline]
pub fn time_get_set<T, Getter, Setter>(
    get_obj: &mut (&mut Getter, &mut Metric),
    get_fn: &mut impl FnMut(&mut Getter, &mut CryptoContext) -> T,
    set_obj: &mut (&mut Setter, &mut Metric),
    set_fn: &mut impl FnMut(&mut Setter, &mut CryptoContext, T),
    context: &mut CryptoContext,
) {
    let start = Metric::now(&mut context.rng);
    let res: T = get_fn(get_obj.0, context);
    *get_obj.1 += start.elapsed(&mut context.rng);

    let start = Metric::now(&mut context.rng);
    set_fn(&mut set_obj.0, context, res);
    *set_obj.1 += start.elapsed(&mut context.rng);
}

/// Rng wrapper that keeps track of the number of bytes generated
pub struct CountingRng<T: RngCore> {
    inner: T,
    byte_counter: usize,
}

impl<T: RngCore> CountingRng<T> {
    /// return the number of bytes generated so far
    pub fn bytes_generated(&self) -> usize {
        self.byte_counter
    }
}

impl<T: RngCore> From<T> for CountingRng<T> {
    fn from(value: T) -> Self {
        Self {
            inner: value,
            byte_counter: 0,
        }
    }
}

impl<T: RngCore> RngCore for CountingRng<T> {
    fn next_u32(&mut self) -> u32 {
        self.byte_counter += 4;
        return self.inner.next_u32();
    }

    fn next_u64(&mut self) -> u64 {
        self.byte_counter += 8;
        return self.inner.next_u64();
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        self.byte_counter += dest.len();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.inner.try_fill_bytes(dest)?;
        self.byte_counter += dest.len();
        return Ok(());
    }
}

// passthrough CryptoRng tagging
impl<T: RngCore + CryptoRng> CryptoRng for CountingRng<T> {}

pub struct CryptoContext<'a> {
    pub rng: &'a mut CountingRng<rand::rngs::ThreadRng>,
}
