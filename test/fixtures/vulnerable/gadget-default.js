// PP-G05: a read with no identified high-value reach. Reported at low severity for a
// human to judge rather than dropped, because reach analysis here is one hop deep.
export function describeJob(job) {
  return `job ${job.humanLabel} is queued`;
}
