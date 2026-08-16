-- PATCH-QAFOX-004B1A-6 rollback
-- Drops only smart-data persistence tables introduced by this patch.
-- Does not drop or alter historical API, plan, run, result, or audit tables.

DROP TABLE IF EXISTS smart_data_graph_bindings CASCADE;
DROP TABLE IF EXISTS smart_data_graph_edges CASCADE;
DROP TABLE IF EXISTS smart_data_graph_nodes CASCADE;
DROP TABLE IF EXISTS smart_data_fixtures CASCADE;
DROP TABLE IF EXISTS smart_data_actions CASCADE;
DROP TABLE IF EXISTS smart_data_runtime_variables CASCADE;
DROP TABLE IF EXISTS smart_data_prerequisites CASCADE;
DROP TABLE IF EXISTS smart_data_auth_flows CASCADE;
DROP TABLE IF EXISTS smart_data_constraints CASCADE;
DROP TABLE IF EXISTS smart_data_fields CASCADE;
DROP TABLE IF EXISTS smart_data_routes CASCADE;
DROP TABLE IF EXISTS smart_data_snapshots CASCADE;
