using './main.bicep'

// Short base name for resources (<= 11 chars keeps generated names globally unique).
param namePrefix = 'cribldec'

// Object ID of the operator/SP that uploads Cribl keys (gets Key Vault Secrets
// Officer). Injected by the pipeline; falls back to empty for manual what-if runs.
param keyAdminObjectId = readEnvironmentVariable('KEY_ADMIN_OBJECT_ID', '')

// location defaults to the resource group location in main.bicep.
