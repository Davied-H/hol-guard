//! Statement text copied verbatim from the original Python schema prefix;
//! `testdata/guard_store/schema_prefix_vectors.json` pins the resulting schema.

pub(crate) const RESUME_CLAIMS: &str = r#"
        create table if not exists guard_continuation_claims (
          request_id text not null,
          offer_hash text not null,
          action text not null,
          state text not null,
          claimed_at text not null,
          lease_expires_at text,
          claim_id text,
          evidence_id text,
          primary key (request_id, offer_hash, action)
        )
        "#;

pub(crate) const RESUME_EFFECTS: &str = r#"
        create table if not exists guard_continuation_effects (
          effect_key text primary key,
          request_id text not null,
          evidence_id text not null,
          event_name text not null,
          created_at text not null
        )
        "#;

pub(crate) const COMMAND_BINDING_COLUMN: &str = r#"command_extensions_json text check (command_extensions_json is null or length(command_extensions_json) between 2 and 2048)"#;

pub(crate) const ACTIVITY: [&str; 21] = [
    r#"
        create table if not exists command_activity (
          activity_id text primary key,
          occurred_at text not null,
          harness text not null,
          hook_phase text not null,
          execution_status text not null,
          proof_level text not null,
          policy_action text,
          decision_reason_code text,
          controlling_rule_id text,
          parse_confidence text,
          uncertainty_class text,
          match_count integer not null check (match_count >= 0),
          prompted integer not null check (prompted in (0, 1)),
          approval_reuse_status text not null,
          receipt_link_status text not null,
          receipt_id text,
          evaluation_latency_bucket text not null,
          persistence_latency_bucket text not null,
          schema_version text not null
        )
        "#,
    r#"
        create table if not exists command_activity_matches (
          activity_id text not null references command_activity(activity_id) on delete cascade,
          ordinal integer not null check (ordinal >= 0),
          extension_id text not null,
          extension_version text not null,
          rule_id text not null,
          rule_version text not null,
          match_class text not null,
          severity text not null,
          default_floor text not null,
          safe_variant_id text,
          schema_version text not null,
          primary key (activity_id, ordinal),
          unique (activity_id, rule_id)
        )
        "#,
    r#"
        create table if not exists command_activity_match_effects (
          activity_id text not null,
          ordinal integer not null,
          effect_class text not null,
          primary key (activity_id, ordinal, effect_class),
          foreign key (activity_id, ordinal)
            references command_activity_matches(activity_id, ordinal) on delete cascade
        )
        "#,
    r#"
        create table if not exists command_activity_correlations (
          activity_id text not null references command_activity(activity_id) on delete cascade,
          kind text not null,
          harness text not null,
          key_id text not null,
          digest text not null,
          primary key (activity_id, kind)
        )
        "#,
    r#"
        create table if not exists command_activity_daily_totals (
          day text primary key,
          total integer not null default 0 check (total >= 0)
        )
        "#,
    r#"
        create table if not exists command_activity_daily_rollups (
          day text not null,
          dimension text not null,
          dimension_value text not null,
          count integer not null default 0 check (count >= 0),
          primary key (day, dimension, dimension_value)
        )
        "#,
    r#"
        create index if not exists idx_command_activity_occurred_at
        on command_activity (occurred_at desc, activity_id desc)
        "#,
    r#"
        create index if not exists idx_command_activity_harness_occurred_at
        on command_activity (harness, occurred_at desc, activity_id desc)
        "#,
    r#"
        create index if not exists idx_command_activity_match_rule
        on command_activity_matches (rule_id, activity_id)
        "#,
    r#"
        create index if not exists idx_command_activity_match_extension
        on command_activity_matches (extension_id, activity_id)
        "#,
    r#"
        create index if not exists idx_command_activity_correlation_lookup
        on command_activity_correlations (kind, harness, key_id, digest)
        "#,
    r#"
        create unique index if not exists idx_command_activity_request_correlation_unique
        on command_activity_correlations (harness, key_id, digest)
        where kind = 'request'
        "#,
    r#"
        create trigger if not exists trg_command_activity_matches_parent
        before insert on command_activity_matches
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity match requires parent activity');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_effects_parent
        before insert on command_activity_match_effects
        when not exists (
          select 1 from command_activity_matches
          where activity_id = new.activity_id and ordinal = new.ordinal
        )
        begin
          select raise(abort, 'command activity effect requires parent match');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_correlations_parent
        before insert on command_activity_correlations
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity correlation requires parent activity');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_delete_children
        after delete on command_activity
        begin
          delete from command_activity_correlations where activity_id = old.activity_id;
          delete from command_activity_matches where activity_id = old.activity_id;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_match_delete_effects
        after delete on command_activity_matches
        begin
          delete from command_activity_match_effects
          where activity_id = old.activity_id and ordinal = old.ordinal;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_id_immutable
        before update of activity_id on command_activity
        when new.activity_id != old.activity_id
        begin
          select raise(abort, 'command activity identity is immutable');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_match_parent_immutable
        before update of activity_id, ordinal on command_activity_matches
        when new.activity_id != old.activity_id or new.ordinal != old.ordinal
        begin
          select raise(abort, 'command activity match parent is immutable');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_effect_parent_immutable
        before update of activity_id, ordinal on command_activity_match_effects
        when new.activity_id != old.activity_id or new.ordinal != old.ordinal
        begin
          select raise(abort, 'command activity effect parent is immutable');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_correlation_parent_immutable
        before update of activity_id on command_activity_correlations
        when new.activity_id != old.activity_id
        begin
          select raise(abort, 'command activity correlation parent is immutable');
        end
        "#,
];

pub(crate) const HEALTH_TABLE: &str = r#"
create table if not exists command_activity_health (
  singleton integer primary key check (singleton = 1),
  dropped_event_count integer not null check (dropped_event_count between 0 and 9223372036854775807),
  persistence_error_count integer not null check (persistence_error_count between 0 and 9223372036854775807),
  last_error_code text check (last_error_code is null or length(last_error_code) between 1 and 64),
  last_error_at text,
  schema_version text not null
)
"#;

pub(crate) const HEALTH_ACTIVE_TABLE: &str = r#"
create table if not exists command_activity_health_active (
  singleton integer primary key check (singleton = 1),
  command_error_active integer not null check (command_error_active in (0, 1)),
  shadow_error_active integer not null check (shadow_error_active in (0, 1)),
  maintenance_error_active integer not null check (maintenance_error_active in (0, 1)),
  foreign key (singleton) references command_activity_health(singleton) on delete cascade
)
"#;

pub(crate) const MAINTENANCE: [&str; 10] = [
    r#"
        create table if not exists command_activity_rollup_membership (
          activity_id text primary key,
          day text not null,
          occurred_at text not null,
          rolled_at text not null,
          detail_present integer not null default 1 check (detail_present in (0, 1))
        )
        "#,
    r#"
        create index if not exists idx_command_activity_rollup_membership_day
        on command_activity_rollup_membership (detail_present, day, activity_id)
        "#,
    r#"
        create index if not exists idx_command_activity_rollup_membership_occurred_at
        on command_activity_rollup_membership (detail_present, occurred_at, activity_id)
        "#,
    r#"
        create table if not exists command_activity_rollup_pending (
          activity_id text primary key,
          occurred_at text not null
        )
        "#,
    r#"
        create table if not exists command_activity_maintenance (
          singleton integer primary key check (singleton = 1),
          last_completed_day text,
          last_run_at text,
          detail_compaction_started_at text,
          rollup_backfill_cursor_occurred_at text,
          rollup_backfill_cursor_activity_id text,
          rollup_backfill_complete integer not null default 0 check (rollup_backfill_complete in (0, 1)),
          last_backfilled_rows integer not null default 0 check (last_backfilled_rows >= 0),
          last_detail_rows_deleted integer not null default 0 check (last_detail_rows_deleted >= 0),
          last_correlation_rows_deleted integer not null default 0 check (last_correlation_rows_deleted >= 0),
          last_aggregate_rows_deleted integer not null default 0 check (last_aggregate_rows_deleted >= 0),
          schema_version text not null
        )
        "#,
    r#"
        create trigger if not exists trg_command_activity_rollup_membership_parent
        before insert on command_activity_rollup_membership
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity rollup membership parent is missing');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_rollup_membership_detail_deleted
        after delete on command_activity
        begin
          update command_activity_rollup_membership
          set detail_present = 0 where activity_id = old.activity_id;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_rollup_pending_parent_inserted
        after insert on command_activity
        begin
          insert or ignore into command_activity_rollup_pending (activity_id, occurred_at)
          values (new.activity_id, new.occurred_at);
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_rollup_pending_membership_inserted
        after insert on command_activity_rollup_membership
        begin
          delete from command_activity_rollup_pending where activity_id = new.activity_id;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_rollup_pending_parent_deleted
        after delete on command_activity
        begin
          delete from command_activity_rollup_pending where activity_id = old.activity_id;
        end
        "#,
];

pub(crate) const API: [&str; 13] = [
    r#"
        create table if not exists command_activity_feedback (
          activity_id text primary key references command_activity(activity_id) on delete cascade,
          label text not null check (
            label in ('should_not_have_interrupted', 'expected_guard_to_stop_this')
          ),
          created_at text not null,
          updated_at text not null,
          schema_version text not null
        )
        "#,
    r#"
        create table if not exists command_activity_invalidations (
          sequence integer primary key autoincrement,
          activity_id text not null
        )
        "#,
    r#"
        create index if not exists idx_command_activity_feedback_label
        on command_activity_feedback (label, updated_at desc, activity_id desc)
        "#,
    r#"
        create index if not exists idx_command_activity_execution_status_occurred_at
        on command_activity (execution_status, occurred_at desc, activity_id desc)
        "#,
    r#"
        create index if not exists idx_command_activity_proof_level_occurred_at
        on command_activity (proof_level, occurred_at desc, activity_id desc)
        "#,
    r#"
        create index if not exists idx_command_activity_approval_reuse_occurred_at
        on command_activity (approval_reuse_status, occurred_at desc, activity_id desc)
        "#,
    r#"
        create index if not exists idx_command_activity_prompted_occurred_at
        on command_activity (prompted, occurred_at desc, activity_id desc)
        "#,
    r#"
        create trigger if not exists trg_command_activity_invalidation_insert
        after insert on command_activity
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_invalidation_update
        after update on command_activity
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_invalidation_delete
        after delete on command_activity
        begin
          insert into command_activity_invalidations (activity_id) values (old.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_feedback_invalidation_insert
        after insert on command_activity_feedback
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_feedback_invalidation_update
        after update on command_activity_feedback
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_feedback_invalidation_delete
        after delete on command_activity_feedback
        begin
          insert into command_activity_invalidations (activity_id) values (old.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        "#,
];

pub(crate) const DISPLAY: [&str; 3] = [
    r#"
        create table if not exists command_activity_invocation (
          activity_id text primary key references command_activity(activity_id) on delete cascade,
          invocation_preview text not null check (
            length(invocation_preview) between 1 and 4096
          )
        )
        "#,
    r#"
        create trigger if not exists trg_command_activity_invocation_immutable
        before update on command_activity_invocation
        begin
          select raise(abort, 'command_activity_invocation_immutable');
        end
        "#,
    r#"
        create trigger if not exists trg_command_activity_invocation_parent
        before insert on command_activity_invocation
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity invocation parent is missing');
        end
        "#,
];
