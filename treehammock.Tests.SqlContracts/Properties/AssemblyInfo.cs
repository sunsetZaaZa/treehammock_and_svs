using Xunit;

// SQL contract tests share one disposable PostgreSQL database per workflow job.
// Several tests apply the canonical baseline, which creates PostgreSQL extensions.
// PostgreSQL extension creation is not safe to race in parallel test execution,
// even when the SQL uses CREATE EXTENSION IF NOT EXISTS.
// Keep this assembly serial so baseline/bootstrap tests do not trip pg_extension_name_index.
[assembly: CollectionBehavior(DisableTestParallelization = true)]