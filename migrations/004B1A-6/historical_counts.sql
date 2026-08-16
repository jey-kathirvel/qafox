-- Record live row counts for historical API tables before and after 004B1A-6.
-- Missing tables are skipped by the Python helper; this file is the operator checklist.

SELECT 'api_discovery_runs' AS table_name, COUNT(*)::bigint AS row_count FROM api_discovery_runs
UNION ALL
SELECT 'api_inventory', COUNT(*)::bigint FROM api_inventory
UNION ALL
SELECT 'api_test_configurations', COUNT(*)::bigint FROM api_test_configurations
UNION ALL
SELECT 'api_test_cases', COUNT(*)::bigint FROM api_test_cases
UNION ALL
SELECT 'api_execution_plans', COUNT(*)::bigint FROM api_execution_plans
UNION ALL
SELECT 'api_execution_plan_cases', COUNT(*)::bigint FROM api_execution_plan_cases
UNION ALL
SELECT 'api_test_runs', COUNT(*)::bigint FROM api_test_runs
UNION ALL
SELECT 'api_test_results', COUNT(*)::bigint FROM api_test_results
UNION ALL
SELECT 'projects', COUNT(*)::bigint FROM projects
UNION ALL
SELECT 'project_audit_events', COUNT(*)::bigint FROM project_audit_events;
